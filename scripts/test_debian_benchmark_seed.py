#!/usr/bin/env python3
"""Run the actual debian-pure Criterion binary against isolated seed fixtures.

Build with cargo bench --locked --no-default-features --features debian-pure
--bench debian_bench --profile dev --no-run, then pass its executable and a new
evidence directory. Requires Linux bubblewrap; missing prerequisites fail.
This is native fixture evidence, not a release timing or guest gate.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess


def run_case(
    binary: Path, evidence: Path, output_root: Path, mode: str
) -> tuple[int, list[Path], str]:
    case = evidence / mode
    apt = case / "apt"
    dpkg = case / "dpkg"
    output = output_root / mode
    (apt / "lists").mkdir(parents=True)
    dpkg.mkdir()
    output.mkdir(parents=True)
    (dpkg / "status").write_text("", encoding="utf-8")
    (apt / "extended_states").write_text("", encoding="utf-8")
    packages = (
        "Package: vim\nVersion: 1.0\nArchitecture: amd64\nSize: 123\n"
        "Installed-Size: 2\nFilename: pool/vim.deb\nDescription: control\n\n"
    )
    if mode == "present":
        packages += (
            "Package: build-essential\nVersion: 1.0\nArchitecture: amd64\n"
            "Size: 321\nInstalled-Size: 4\nFilename: pool/build-essential.deb\n"
            "Description: present seed control\n\n"
        )
    (apt / "lists" / "fixture_dists_stable_main_binary-amd64_Packages").write_text(
        packages, encoding="utf-8"
    )
    command = [
        "bwrap", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid",
        "--unshare-net", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/var/lib", "--ro-bind", str(apt), "/var/lib/apt",
        "--ro-bind", str(dpkg), "/var/lib/dpkg", "--tmpfs", "/home",
        "--dir", "/home/benchmark", "--bind", str(output), "/home/benchmark/evidence",
        "--ro-bind", str(binary), "/home/benchmark/debian-bench",
        "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/home/benchmark",
        "--setenv", "XDG_CACHE_HOME", "/home/benchmark/.cache",
        "--setenv", "CRITERION_HOME", "/home/benchmark/evidence",
        "/home/benchmark/debian-bench", "--bench",
        "^debian_resolver/resolve_large_package$", "--noplot",
    ]
    (case / "command.json").write_text(json.dumps(command, indent=2), encoding="utf-8")
    result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
    log = result.stdout + result.stderr
    (case / "benchmark.log").write_text(log, encoding="utf-8")
    (case / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result.returncode, list(output.rglob("sample.json")), log


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--criterion-output", type=Path,
                        help="New output directory on a native Linux filesystem")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if shutil.which("bwrap") is None:
        raise RuntimeError("HARNESS_ERROR: bubblewrap is required")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    output_root = (args.criterion_output or evidence / "output").resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    missing_exit, missing_samples, missing_log = run_case(binary, evidence, output_root, "missing")
    present_exit, present_samples, present_log = run_case(binary, evidence, output_root, "present")
    if "Criterion.rs ERROR:" in missing_log + present_log:
        raise RuntimeError("HARNESS_ERROR: Criterion reported an output error; inspect benchmark.log")
    if present_exit != 0 or not present_samples:
        raise RuntimeError(f"HARNESS_ERROR: present seed did not sample: {present_log}")
    for sample in present_samples:
        data = json.loads(sample.read_text(encoding="utf-8"))
        if len(data["iters"]) != 30 or any(count <= 0 for count in data["iters"]):
            raise RuntimeError("HARNESS_ERROR: present seed samples are incomplete")
    print("PASS: present build-essential seed admits 30 real Criterion samples")
    if missing_exit == 0 or missing_samples:
        raise AssertionError(
            f"FAIL: missing build-essential seed admitted benchmark: "
            f"exit={missing_exit}, sample_files={len(missing_samples)}"
        )
    if "Package 'build-essential' not found in repositories" not in missing_log:
        raise RuntimeError(f"HARNESS_ERROR: unrelated missing-seed failure: {missing_log}")
    print("PASS: missing build-essential seed fails without admitting samples")


if __name__ == "__main__":
    main()

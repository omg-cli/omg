"""Run a bounded source-extracted completion regression with the real scorer.

This is a fast source-method check, not a full-crate, CLI, daemon or guest gate.
Run the committed integration test against the full crate for native admission.
The output directory must be task-owned scratch; generated files are retained.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument("--source-ref", help="Optional immutable baseline Git SHA")
    source_group.add_argument("--source-file", type=Path, help="Exported baseline for cross-OS worktrees")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.source_ref:
        source = subprocess.check_output(
            ["git", "show", f"{args.source_ref}:src/core/completion.rs"], cwd=root
        ).decode("utf-8")
    elif args.source_file:
        source = args.source_file.read_text(encoding="utf-8")
    else:
        source = (root / "src/core/completion.rs").read_text(encoding="utf-8")
    print("completion_source_sha256=" + hashlib.sha256(source.encode()).hexdigest(), flush=True)
    start = source.index("    pub fn fuzzy_match(")
    end = source.index("    /// Probe context", start)
    methods = source[start:end]
    # Extract the production methods verbatim, including nucleo scoring and sort.
    generated = """use nucleo_matcher::{Config, Matcher, Utf32String,
        pattern::{CaseMatching, Normalization, Pattern}};
pub mod core { pub mod completion {
use super::super::*;
pub struct CompletionEngine;
impl CompletionEngine {
pub fn new() -> Self { Self }
""" + methods + "\n} } }\n"
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "src").mkdir(exist_ok=True)
    (output / "src/lib.rs").write_text(generated, encoding="utf-8")
    (output / "src/allocations.rs").write_bytes(
        (root / "tests/completion_allocations.rs").read_bytes()
    )
    (output / "Cargo.toml").write_text('''[package]
name = "completion-allocation-probe"
version = "0.0.0"
edition = "2024"
[lib]
name = "omg_lib"
[[test]]
name = "allocations"
path = "src/allocations.rs"
[dependencies]
nucleo-matcher = "=0.3.1"
''', encoding="utf-8")
    environment = os.environ.copy()
    environment["CARGO_BUILD_JOBS"] = "2"
    environment.setdefault("CARGO_TARGET_DIR", str(output / "target"))
    return subprocess.call(
        ["cargo", "test", "--offline", "--manifest-path", str(output / "Cargo.toml"),
         "--test", "allocations", "--", "--nocapture"], env=environment, cwd=root
    )


if __name__ == "__main__":
    raise SystemExit(main())

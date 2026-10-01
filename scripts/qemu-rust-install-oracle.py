#!/usr/bin/env python3
"""Prove the installed native Rust fixture; never select a host rustc fallback.

Pin identity: https://static.rust-lang.org/dist/channel-rust-1.85.0.toml
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import time
import tomllib

PIN = "1.85.0"
RELEASE = "1.85.0 (4d91de4e4 2025-02-17)"
COMPONENTS = {"rustc", "cargo", "rust-std", "rustfmt", "clippy", "rust-docs"}
GUARD = b"#!/bin/sh\nprintf 'OMG_OTHER_RUNTIME_OK\\n'\n"
HOSTS = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_directory(path, private=False):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(), f"foreign or non-directory fixture: {path}"
    assert not private or stat.S_IMODE(info.st_mode) == 0o700, f"fixture directory is not private: {path}"


def guard_state(root):
    base = root / "runtime-data/versions/other-guard"
    assert base.is_dir() and not base.is_symlink(), "other runtime directory was replaced"
    current = base / "current"
    binary = base / "1.0.0/bin/guard"
    assert current.is_symlink() and os.readlink(current) == "1.0.0", "other runtime current link changed"
    assert stat.S_ISREG(binary.lstat().st_mode) and binary.read_bytes() == GUARD, "other runtime executable changed"
    return {"current": os.readlink(current), "sha256": sha(binary), "mode": stat.S_IMODE(binary.stat().st_mode)}


def prepare(root):
    assert os.geteuid() != 0, "Rust installation fixture requires an unprivileged user"
    owned_directory(root)
    linker = shutil.which("cc")
    assert linker is not None, "native C linker prerequisite is missing"
    linker_identity, _ = run([linker, "--version"], 5)
    assert linker_identity.stdout.strip(), "native C linker did not identify itself"
    for name in ("runtime-home", "runtime-data", "runtime-cache", "runtime-config"):
        (root / name).mkdir(mode=0o700)
        owned_directory(root / name, private=True)
    guard = root / "runtime-data/versions/other-guard/1.0.0/bin"
    guard.mkdir(parents=True, mode=0o700)
    (guard / "guard").write_bytes(GUARD)
    (guard / "guard").chmod(0o700)
    (guard.parent.parent / "current").symlink_to("1.0.0")
    state = {"guard": guard_state(root), "startedMonotonicNS": time.monotonic_ns(),
             "nativeLinker": {"path": linker, "identity": linker_identity.stdout}}
    (root / "rust-before.json").write_text(json.dumps(state))


def run(command, timeout):
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=True)
    return result, time.monotonic() - started


def check(root):
    assert os.geteuid() != 0, "Rust installation proof requires an unprivileged user"
    owned_directory(root)
    for name in ("runtime-home", "runtime-data", "runtime-cache", "runtime-config"):
        owned_directory(root / name, private=True)
    before = json.loads((root / "rust-before.json").read_text())
    assert guard_state(root) == before["guard"], "other runtime state changed during Rust installation"
    host = HOSTS[platform.machine()]
    base = root / "runtime-data/versions/rust"
    expected = base / f"{PIN}-{host}"
    owned_directory(base)
    owned_directory(expected)
    current = base / "current"
    assert current.is_symlink() and current.resolve(strict=True) == expected, "Rust current does not resolve inside the exact installed pin"
    assert not (expected / ".omg-installing").exists(), "Rust publication left an incomplete marker"
    metadata = expected / ".omg-toolchain.toml"
    assert stat.S_ISREG(metadata.lstat().st_mode), "Rust metadata is not a regular file"
    state = tomllib.loads(metadata.read_text())
    assert state["release"] == RELEASE and set(state["components"]) == COMPONENTS, "installed Rust release or default components differ"
    compiler = expected / "bin/rustc"
    assert stat.S_ISREG(compiler.lstat().st_mode) and compiler.resolve(strict=True) == compiler, "compiler is not confined to the installed pin"
    identity, version_time = run([str(compiler), "--version"], 10)
    assert identity.stdout == f"rustc {RELEASE}\n" and not identity.stderr, "installed compiler identity differs from the verified manifest"
    fixture = root / "rust-compile-probe"
    fixture.mkdir(mode=0o700)
    source, binary = fixture / "main.rs", fixture / "probe"
    source.write_text('fn main() { assert_eq!(6 * 7, 42); println!("OMG_RUST_RUNTIME_OK:42"); }\n')
    compilation, compile_time = run([str(compiler), str(source), "-o", str(binary)], 60)
    assert not compilation.stdout and not compilation.stderr, "Rust compilation emitted unexpected diagnostics"
    assert stat.S_ISREG(binary.lstat().st_mode) and binary.resolve(strict=True) == binary, "probe is not a confined compiled executable"
    execution, execute_time = run([str(binary)], 10)
    assert execution.stdout == "OMG_RUST_RUNTIME_OK:42\n" and not execution.stderr, "compiled Rust program did not execute the expected behavior"
    sibling, sibling_time = run([str(root / "runtime-data/versions/other-guard/current/bin/guard")], 5)
    assert sibling.stdout == "OMG_OTHER_RUNTIME_OK\n" and not sibling.stderr, "other installed runtime no longer executes"
    assert guard_state(root) == before["guard"], "other runtime changed during the compiler probe"
    proof = {"pin": PIN, "host": host, "uid": os.geteuid(), "release": RELEASE,
             "components": sorted(COMPONENTS), "compilerSHA256": sha(compiler),
             "programSHA256": sha(binary), "programOutput": execution.stdout,
             "otherRuntime": before["guard"], "otherRuntimeOutput": sibling.stdout,
             "nativeLinker": before["nativeLinker"],
             "elapsedSeconds": {"installToProof": (time.monotonic_ns() - before["startedMonotonicNS"]) / 1e9,
                                "version": version_time, "compile": compile_time,
                                "execute": execute_time, "sibling": sibling_time}}
    (root / "rust-install-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof, sort_keys=True))
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "check"))
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    assert args.root.is_absolute() and args.root.resolve(strict=True) == args.root, "fixture root is not a canonical absolute directory"
    if args.operation == "prepare":
        prepare(args.root)
    else:
        check(args.root)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"assertion failed: native Rust installation: {error}", file=sys.stderr)
        raise SystemExit(1) from error

# Debian and Ubuntu Doctor Health Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `omg doctor` report actual Debian package database and APT index readability/parseability on Debian and Ubuntu, with guest failures that prove the verdict.

**Architecture:** Reuse the read-only dpkg inventory parser and the APT Packages parser already used by the Debian backend. Keep status and index outcomes separate in doctor so each contributes one health issue. Add two confined guest fixtures that bind malformed data inside a private mount namespace, run the submitted binary as the unprivileged guest, and compare its issue count with an unmodified baseline.

**Tech Stack:** Rust, Bash, QEMU inventory TSV, Python contract tests.

**Spec:** [Issue #676](https://github.com/omg-cli/omg/issues/676).

## Global Constraints

- Doctor must be read-only and must not refresh repositories.
- Both Debian and Ubuntu must run the same real probes and guest failure cases.
- Every passing guest fixture must prove a product exit, failure detail, and exactly one added issue.
- Preserve trusted-main QEMU issue reporting and untrusted-PR token boundaries.

## Review Focus

- Empty dpkg status must fail even though parsing an empty string succeeds.
- A valid empty Packages index must remain valid; a corrupt compressed stream or malformed stanza must fail.
- A repository containing only an empty Packages index is valid too: `apt-ftparchive packages` emits one record per `.deb` and emits none for an empty directory. Doctor checks structural health, not whether a repository publishes useful packages.
- A broken second index must fail even when the first parses correctly.
- A Packages stanza missing or duplicating a required Package, Version, or Architecture field must fail in both doctor and the live backend. Debian requires these fields in binary package control records, from which Packages indexes are generated.
- Plain, gzip, lz4, and xz index decoding must share the existing 512 MiB output budget.
- Missing mount namespace support must be a harness failure, never a product pass.
- A failed namespace creation or bind mount must emit the setup sentinel/120 before the product starts, so QEMU records HARNESS_ERROR rather than treating the host capability failure as Doctor behavior.
- Native Debian and Ubuntu results must be distinguished from WSL and fake-runner evidence.

### Task 1: Backend validation

**Files:** `src/package_managers/debian_db/db.rs`, `src/cli/doctor.rs`

- [x] Add failing unit tests for empty/corrupt dpkg status, valid/invalid APT indexes and per-file scanning.
- [x] Expose read-only backend validation functions with exact file/directory inputs for hermetic tests.
- [x] Call them from doctor and count each error separately, with bounded terminal-safe diagnostics.
- [x] Use trusted `apt-get` lookup in the dependency check.
- [x] Run focused Rust tests and clippy for the Debian feature set.

### Task 2: Guest proof

**Files:** `scripts/qemu-debian-doctor-check.sh`, `scripts/qemu-inventory.sh`, `scripts/benchmark-qemu.sh`, `tests/cli_behavior_inventory.tsv`, `tests/qemu-inventory-policy.json`, `scripts/test_qemu_output_contracts.py`

- [x] Add failing fake-runner tests proving a command that merely exits 1 is rejected.
- [x] Add separate dpkg and APT corruption rows for Debian and Ubuntu.
- [x] Bind each malformed fixture inside a private mount namespace and run the submitted binary as the guest user.
- [x] Require exactly one added health issue and the expected failed health line, and preserve raw logs.
- [x] Run policy, output-contract and release-smoke checks, then run the available native WSL checks.

Debian WSL and Ubuntu 26.04 WSL each built a native Debian-feature binary and passed both private-mount fault probes. Ubuntu 24.04 WSL denies mount namespace creation, so hosted QEMU remains the required Ubuntu 24.04 proof. The policy file is 946,240 bytes, under the current 1 MiB policy reader cap; capacity is tracked separately.

Format sources: [Debian binary control fields](https://manpages.debian.org/unstable/dpkg-dev/deb-control.5.en.html), [deb822 field rules](https://manpages.debian.org/bookworm/dpkg-dev/deb822.5.en.html), and [Packages index generation](https://manpages.debian.org/trixie/apt-utils/apt-ftparchive.1.en.html).

### Task 3: Ship

- [ ] Rebase onto latest main after dependent PRs merge, review the exact diff and current-head checks.
- [ ] Commit, push, and open a PR closing #676; do not merge from this worktree.

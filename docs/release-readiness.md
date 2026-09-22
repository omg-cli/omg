---
title: Release readiness
sidebar_position: 60
description: Checks maintainers complete before publishing a release
---

# Release readiness checklist

> **Who this page is for:** OMG maintainers and contributors. It documents the release checklist.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Use this checklist before tagging a release. A successful build does not establish runtime coverage, reproducibility of every binary byte, or platform parity.

## 1) Local Quality Gates

```bash
cargo fmt --all -- --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

## 2) Feature-Scoped Validation

Run feature-scoped checks to match CI behavior and avoid false negatives from mutually exclusive platform stacks.

```bash
# Portable baseline
cargo clippy --all-targets --no-default-features --features pgp,license --locked -- -D warnings

# Arch
cargo clippy --all-targets --no-default-features --features arch,license --locked -- -D warnings

# Debian (requires libapt-pkg-dev)
cargo clippy --all-targets --no-default-features --features debian --locked -- -D warnings

# Fedora
cargo clippy --all-targets --no-default-features --features fedora,license --locked -- -D warnings

# macOS
cargo clippy --all-targets --no-default-features --features macos,license --locked -- -D warnings
```

## 3) Platform Build Prerequisites

- Debian/Ubuntu (`--features debian`): `libapt-pkg-dev`, `clang`, `cmake`
- Arch (`--features arch`): `libalpm` toolchain
- Fedora (`--features fedora`): rpm/sqlite development stack
- macOS: Xcode Command Line Tools

## 4) CI Expectations

- Quick gate passes (`fmt`, portable `clippy`, `check`, portable tests)
- Linux matrix passes (Arch, Debian Bookworm and Trixie, Fedora, and the Ubuntu job)
- Native macOS job passes. Linux jobs exercise the distribution backend, not WSL integration; verify WSL separately before claiming coverage
- Coverage job completes and uploads merged report

## 5) Ship Criteria

- No new warnings/errors in scoped `clippy` runs
- No regressions in critical tests (`e2e_package_operations`, daemon cache/lifecycle)
- README and CONTRIBUTING reflect current Rust requirement (1.95.0+)
- All six release archives build successfully: Arch, Debian Bookworm, Debian
  Trixie, Ubuntu, Fedora, and Apple Silicon macOS.
- APT 6 and APT 7 staged smoke passes before publication. The selected
  published-archive smoke cases also pass; retain artifact hashes and failures.
- Daemon-dependent commands have a matching `omgd` binary in the tested installation
- Archive checksums and tag/workflow-bound attestations verify
- Generated release SBOM is present and the generation step leaves `Cargo.lock` unchanged
- Public docs distinguish local candidate evidence from published-artifact results and make no SLSA-level or compliance-certification claim

## Where to go next

- [Release operations](./release-operations.md) covers publication and R2 recovery.
- [QA loop](./qa-loop.md) explains how failed cases become issues.
- [QEMU local guide](./qemu-local.md) describes guest evidence and its limits.

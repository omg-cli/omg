# Rust CI/CD Best Practices 2025-2026

> **Who this page is for:** OMG maintainers and contributors. It documents a research note on continuous integration.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Historical research examples, not this repository's active CI configuration. Package versions, speed claims, Rust APIs, and workflow snippets below have not been revalidated as current recommendations. In particular, do not copy `--all-features` examples into OMG: its native backend features are not universally compatible. Use [CONTRIBUTING.md](../CONTRIBUTING.md), the checked-in workflows, and current toolchain pins. This documentation audit classifies the archive; it does not certify every historical snippet.

## Table of Contents

1. [Rust CI/CD Pipeline Optimization](#1-rust-cicd-pipeline-optimization)
2. [Test Hardening Strategies](#2-test-hardening-strategies)
3. [GitHub Actions Optimization](#3-github-actions-optimization)
4. [Cross-Platform Testing](#4-cross-platform-testing)
5. [Security Scanning](#5-security-scanning)
6. [Complete Example Workflow](#6-complete-example-workflow)

---

## 1. Rust CI/CD Pipeline Optimization

### 1.1 Rust 2024 Edition and Modern Features

Rust 1.85+ (February 2025) stabilized the 2024 edition with several CI-relevant improvements:

- **Rustdoc combined tests**: Doctests are now combined into a single executable, significantly improving performance
- **Rust-version aware resolver**: The default dependency resolver now considers the `rust-version` field
- **Cargo cache cleanup**: Cargo 1.88+ automatically cleans up its cache
- **Async closures**: Support for `async || {}` closures

**Cargo.toml configuration for Edition 2024:**
```toml
[package]
name = "your-project"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[profile.dev]
# Faster dev builds
opt-level = 0
debug = true
incremental = true

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = true

[profile.ci]
inherits = "release"
lto = "thin"
debug = false
```

### 1.2 Faster Linkers (mold / wild)

Using faster linkers can significantly reduce build times:

**.cargo/config.toml:**
```toml
# Use mold linker on Linux for faster linking
[target.'cfg(target_os = "linux")']
rustflags = ["-C", "link-arg=-fuse-ld=mold"]

# Use lld on Windows
[target.'cfg(target_os = "windows")']
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

# macOS uses the default linker (already fast)
```

**Note:** The Wild linker (written in Rust) is emerging as a potential successor to mold, with plans for incremental linking support. Watch the project for future CI improvements.

### 1.3 Compilation Caching with sccache

sccache wraps rustc and caches compilation artifacts:

```yaml
- name: Setup sccache
  uses: mozilla-actions/sccache-action@v0.0.9

- name: Configure sccache
  run: |
    echo "SCCACHE_GHA_ENABLED=true" >> $GITHUB_ENV
    echo "RUSTC_WRAPPER=sccache" >> $GITHUB_ENV
    echo "SCCACHE_CACHE_SIZE=2G" >> $GITHUB_ENV
```

### 1.4 cargo-nextest for Faster Test Execution

cargo-nextest provides up to 3x faster test execution through parallel test isolation:

```yaml
- name: Install nextest
  uses: taiki-e/install-action@nextest

- name: Run tests
  run: cargo nextest run --all-features --profile ci
```

**.config/nextest.toml:**
```toml
[profile.ci]
retries = 2
fail-fast = false
test-threads = "num-cpus"

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"
```

---

## 2. Test Hardening Strategies

### 2.1 Property-Based Testing with proptest

proptest generates random inputs to verify system invariants:

```rust
// Cargo.toml
// [dev-dependencies]
// proptest = "1.4"

use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parser_roundtrip(s in "[a-z]{1,100}") {
        let parsed = parse(&s)?;
        let serialized = serialize(&parsed);
        prop_assert_eq!(s, serialized);
    }

    #[test]
    fn test_arithmetic_properties(a in 0i32..1000, b in 0i32..1000) {
        // Commutative property
        prop_assert_eq!(add(a, b), add(b, a));
        // Identity
        prop_assert_eq!(add(a, 0), a);
    }
}
```

### 2.2 Fuzzing with cargo-fuzz

Fuzzing finds edge cases through mutation-based input generation:

```bash
# Install (requires nightly)
cargo install cargo-fuzz

# Initialize fuzzing
cargo fuzz init

# Create fuzz target
cargo fuzz add my_parser
```

**fuzz/fuzz_targets/my_parser.rs:**
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use my_crate::parse;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse(s);
    }
});
```

**CI Integration for fuzzing:**
```yaml
fuzz:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly
    - name: Install cargo-fuzz
      run: cargo install cargo-fuzz
    - name: Run fuzzer
      run: cargo fuzz run my_parser -- -max_total_time=300
```

### 2.3 Mutation Testing with cargo-mutants

cargo-mutants identifies untested code paths:

```yaml
mutation-testing:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - name: Install cargo-mutants
      run: cargo install cargo-mutants
    - name: Run mutation tests
      run: cargo mutants --timeout-multiplier 2 --jobs 4
```

**.cargo/mutants.toml:**
```toml
# Exclude slow or flaky tests from mutation testing
exclude_globs = [
    "tests/integration/**",
    "**/generated/**",
]

# Use nextest for faster mutation testing
test_tool = "nextest"
```

**For large projects, use sharding:**
```yaml
mutation-testing:
  runs-on: ubuntu-latest
  strategy:
    matrix:
      shard: [1, 2, 3, 4]
  steps:
    - name: Run mutation tests (shard ${{ matrix.shard }}/4)
      run: cargo mutants --shard ${{ matrix.shard }}/4
```

### 2.4 Preventing Flaky Tests

**Deterministic test configuration:**

```rust
// Use deterministic seeds for tests involving randomness
#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn deterministic_rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(42)
    }

    #[test]
    fn test_with_deterministic_random() {
        let mut rng = deterministic_rng();
        // Test logic...
    }
}
```

**rust-toolchain.toml for reproducible builds:**
```toml
[toolchain]
channel = "1.85.0"
components = ["rustfmt", "clippy", "rust-src"]
targets = ["x86_64-unknown-linux-gnu"]
```

**Isolation strategies:**
- Use unique port numbers per test for network tests
- Create isolated temp directories per test
- Mock time/clock dependencies
- Avoid `sleep()` - use condition-based waits instead

---

## 3. GitHub Actions Optimization

### 3.1 Caching Strategies

**Swatinem/rust-cache (recommended for simplicity):**
```yaml
- uses: Swatinem/rust-cache@v2
  with:
    shared-key: "ci-${{ matrix.os }}"
    cache-targets: true
    cache-on-failure: true
    cache-all-crates: true
```

**sccache (recommended for large projects):**
```yaml
env:
  SCCACHE_GHA_ENABLED: "true"
  RUSTC_WRAPPER: "sccache"

steps:
  - uses: mozilla-actions/sccache-action@v0.0.9
```

**Key differences:**
- `rust-cache`: Caches the entire target directory, simpler setup
- `sccache`: Caches individual compilation units, more efficient for large projects, concurrent downloads

### 3.2 Parallel Job Configuration

```yaml
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --all-features

  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --check

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --all-features -- -D warnings

  test:
    needs: [check]  # Only run tests if check passes
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@nextest
      - run: cargo nextest run --all-features
```

### 3.3 Matrix Builds

```yaml
test:
  strategy:
    fail-fast: false
    matrix:
      include:
        - os: ubuntu-latest
          target: x86_64-unknown-linux-gnu
        - os: macos-latest
          target: x86_64-apple-darwin
        - os: macos-latest
          target: aarch64-apple-darwin
        - os: windows-latest
          target: x86_64-pc-windows-msvc

  runs-on: ${{ matrix.os }}
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        targets: ${{ matrix.target }}
    - uses: Swatinem/rust-cache@v2
      with:
        shared-key: "test-${{ matrix.target }}"
    - run: cargo test --target ${{ matrix.target }}
```

### 3.4 MSRV Testing

```yaml
msrv:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@master
      with:
        toolchain: "1.75.0"  # Your MSRV
    - uses: Swatinem/rust-cache@v2
    - run: cargo check --all-features
```

### 3.5 Binary Installation Optimization

Use `taiki-e/install-action` instead of `cargo install`:

```yaml
- uses: taiki-e/install-action@v2
  with:
    tool: cargo-nextest,cargo-audit,cargo-deny
```

---

## 4. Cross-Platform Testing

### 4.1 Platform Matrix Configuration

```yaml
test:
  strategy:
    fail-fast: false
    matrix:
      include:
        # Linux
        - os: ubuntu-latest
          target: x86_64-unknown-linux-gnu
          cross: false
        - os: ubuntu-latest
          target: x86_64-unknown-linux-musl
          cross: true
        - os: ubuntu-latest
          target: aarch64-unknown-linux-gnu
          cross: true

        # macOS
        - os: macos-latest
          target: x86_64-apple-darwin
          cross: false
        - os: macos-latest
          target: aarch64-apple-darwin
          cross: false

        # Windows
        - os: windows-latest
          target: x86_64-pc-windows-msvc
          cross: false
        - os: windows-latest
          target: x86_64-pc-windows-gnu
          cross: false

  runs-on: ${{ matrix.os }}
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        targets: ${{ matrix.target }}

    - name: Install cross
      if: matrix.cross
      uses: taiki-e/install-action@cross

    - name: Test (native)
      if: "!matrix.cross"
      run: cargo test --target ${{ matrix.target }}

    - name: Test (cross)
      if: matrix.cross
      run: cross test --target ${{ matrix.target }}
```

### 4.2 Platform-Specific Code Testing

```rust
// Use cfg attributes for platform-specific code
#[cfg(target_os = "linux")]
fn platform_specific() {
    // Linux implementation
}

#[cfg(target_os = "macos")]
fn platform_specific() {
    // macOS implementation
}

#[cfg(target_os = "windows")]
fn platform_specific() {
    // Windows implementation
}

// Test each platform
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_specific() {
        // Linux-specific tests
    }
}
```

### 4.3 Static Linking for Portability

For Linux, use musl for fully static binaries:

```yaml
build-static:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
      with:
        targets: x86_64-unknown-linux-musl
    - name: Install musl-tools
      run: sudo apt-get install -y musl-tools
    - name: Build static binary
      run: cargo build --release --target x86_64-unknown-linux-musl
```

---

## 5. Security Scanning

### 5.1 cargo-audit (Vulnerability Scanning)

```yaml
security-audit:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: taiki-e/install-action@cargo-audit
    - name: Run security audit
      run: cargo audit --deny warnings
```

### 5.2 cargo-deny (Comprehensive Policy Enforcement)

**deny.toml:**
```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "MPL-2.0",
]
copyleft = "deny"
unlicensed = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"
deny = [
    # Deny specific problematic crates
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**CI Integration:**
```yaml
cargo-deny:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: EmbarkStudios/cargo-deny-action@v2
```

### 5.3 cargo-geiger (Unsafe Code Audit)

```yaml
unsafe-audit:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - name: Install cargo-geiger
      run: cargo install cargo-geiger
    - name: Run unsafe audit
      run: cargo geiger --all-features
```

### 5.4 Supply Chain Security with Sigstore

The Rust Foundation is working on Sigstore integration for crate signing. For now, you can sign release artifacts:

```yaml
release:
  runs-on: ubuntu-latest
  permissions:
    id-token: write
    contents: write
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable

    - name: Build release
      run: cargo build --release

    - name: Install cosign
      uses: sigstore/cosign-installer@v3

    - name: Sign artifact
      run: |
        cosign sign-blob \
          --yes \
          --output-signature target/release/myapp.sig \
          target/release/myapp
```

### 5.5 Dependency Scanning with Dependabot

**.github/dependabot.yml:**
```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    groups:
      rust-dependencies:
        patterns:
          - "*"
    ignore:
      - dependency-name: "*"
        update-types: ["version-update:semver-major"]
```

### 5.6 SAST with Miri

Miri detects undefined behavior in unsafe code:

```yaml
miri:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@nightly
      with:
        components: miri
    - name: Run Miri
      run: cargo miri test
      env:
        MIRIFLAGS: "-Zmiri-disable-isolation"
```

---

## 6. Complete Example Workflow

**.github/workflows/ci.yml:**
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"
  CARGO_INCREMENTAL: 0

jobs:
  # Quick checks that run in parallel
  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --check

  clippy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --all-features --all-targets -- -D warnings

  doc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo doc --no-deps --all-features
        env:
          RUSTDOCFLAGS: "-D warnings"

  # Security checks
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-audit,cargo-deny
      - name: Security audit
        run: cargo audit --deny warnings
      - name: Dependency check
        run: cargo deny check

  # Main test matrix
  test:
    needs: [fmt, clippy]
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: macos-latest
            target: x86_64-apple-darwin
          - os: macos-latest
            target: aarch64-apple-darwin
          - os: windows-latest
            target: x86_64-pc-windows-msvc

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - uses: Swatinem/rust-cache@v2
        with:
          shared-key: "test-${{ matrix.target }}"
      - uses: taiki-e/install-action@nextest

      - name: Run tests
        run: cargo nextest run --all-features --target ${{ matrix.target }}

      - name: Run doctests
        run: cargo test --doc --all-features

  # MSRV check
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.75.0"  # Adjust to your MSRV
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --all-features

  # Coverage (optional)
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@cargo-llvm-cov
      - name: Generate coverage
        run: cargo llvm-cov --all-features --lcov --output-path lcov.info
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false

  # Miri for unsafe code (optional, run on schedule)
  miri:
    if: github.event_name == 'schedule' || contains(github.event.head_commit.message, '[miri]')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: miri
      - uses: Swatinem/rust-cache@v2
      - name: Run Miri
        run: cargo miri test
        env:
          MIRIFLAGS: "-Zmiri-disable-isolation"
```

**.github/workflows/release.yml:**
```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  id-token: write

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: myapp
          - os: ubuntu-latest
            target: x86_64-unknown-linux-musl
            artifact: myapp
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: myapp
          - os: macos-latest
            target: aarch64-apple-darwin
            artifact: myapp
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: myapp.exe

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Install musl-tools
        if: contains(matrix.target, 'musl')
        run: sudo apt-get install -y musl-tools

      - uses: Swatinem/rust-cache@v2

      - name: Build
        run: cargo build --release --target ${{ matrix.target }}

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.target }}
          path: target/${{ matrix.target }}/release/${{ matrix.artifact }}

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - uses: softprops/action-gh-release@v2
        with:
          files: "**/*"
          generate_release_notes: true
```

---

## Quick Reference

### Performance Optimizations Checklist

- [ ] Use `sccache` or `rust-cache` for caching
- [ ] Use `cargo-nextest` for parallel test execution
- [ ] Configure faster linker (mold on Linux)
- [ ] Split jobs to run in parallel (fmt, clippy, test)
- [ ] Use `taiki-e/install-action` for binary installation
- [ ] Set `CARGO_INCREMENTAL=0` in CI (cache handles incrementality)

### Security Checklist

- [ ] Run `cargo audit` on every PR
- [ ] Configure `cargo deny` for license and ban policies
- [ ] Enable Dependabot for Cargo dependencies
- [ ] Run `cargo geiger` to audit unsafe code
- [ ] Run Miri periodically for unsafe code validation
- [ ] Sign release artifacts with Sigstore

### Test Hardening Checklist

- [ ] Add property-based tests with `proptest`
- [ ] Set up fuzzing targets with `cargo-fuzz`
- [ ] Run mutation testing with `cargo-mutants`
- [ ] Pin toolchain version in `rust-toolchain.toml`
- [ ] Use deterministic seeds for RNG in tests
- [ ] Avoid timing-based tests (use condition waits)

---

## Sources

- [Setting up effective CI/CD for Rust projects - Shuttle](https://www.shuttle.dev/blog/2025/01/23/setup-rust-ci-cd)
- [Optimizing CI/CD pipelines in Rust - LogRocket](https://blog.logrocket.com/optimizing-ci-cd-pipelines-rust-projects/)
- [Fast Rust Builds with sccache - Depot](https://depot.dev/blog/sccache-in-github-actions)
- [Swatinem/rust-cache - GitHub](https://github.com/Swatinem/rust-cache)
- [cargo-nextest Documentation](https://nexte.st/)
- [cargo-mutants Documentation](https://mutants.rs/)
- [Rust Security Auditing Guide 2026 - Sherlock](https://sherlock.xyz/post/rust-security-auditing-guide-2026)
- [Rust Foundation Supply Chain Security](https://rustfoundation.org/media/improving-supply-chain-security-for-rust-through-artifact-signing/)
- [Announcing Rust 1.85.0 and Rust 2024](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/)
- [Effective Rust - CI Best Practices](https://effective-rust.com/ci.html)
- [mold: A Modern Linker](https://github.com/rui314/mold)

# OMG CI/CD & Documentation-Backed TDD Architecture

OMG follows a 4-tier CI/CD model aligned with modern Rust systems and package-manager projects (`uv`, `mise`, `pixi`, `nix-installer`, `dnf5`), emphasizing fast hermetic feedback on pull requests and deterministic multi-distro OCI containers instead of slow, flaky QEMU full-system VMs on every commit.

## 4-Tier Pipeline

### Tier 1 — Fast Hermetic PR Gate (`ci.yml`, `ci-security.yml`)
- **Formatting, linting, supply chain:** `cargo fmt --check`, `cargo clippy`, `cargo deny`, and `zizmor` static analysis on `.github/workflows` and `.github/actions`.
- **Unit & contract tests:** Hermetic unit tests (including local TCP fault-injection fixtures for HTTP/2 `REFUSED_STREAM`, low-speed download stalls, metadata timeouts, and `doctor` connectivity) plus documentation-backed CLI and schema tests (`tests/cli_doc_contracts.rs`).
- **Docs & policy audits:** `make audit-docs`, ALPM pin checks, and debt ratchets.

### Tier 2 — Multi-Distro & Native ARM64 Container E2E (`distro-e2e.yml`)
- Replaces the legacy QEMU matrix on pull requests and `main` pushes using [`scripts/distro-e2e.sh`](../scripts/distro-e2e.sh).
- Tests real native package managers and ABI linking directly inside official distro containers:
  - **x86_64 (`ubuntu-24.04`):** `archlinux:latest` (`pacman`/`alpm`), `debian:bookworm`, `debian:trixie`, `ubuntu:24.04` (`apt`/`dpkg`), `fedora:latest` (`dnf`/SQLite).
  - **Native ARM64 (`ubuntu-24.04-arm`):** `debian:bookworm`, `ubuntu:24.04`, `fedora:latest` running natively without requiring `/dev/kvm`.
- **Native `systemd` + `omgd` check:** Verifies real `omgd` socket IPC and `systemd` PID 1 behavior directly on the Ubuntu host runner.

### Tier 3 — Scheduled / On-Demand Deep Verification (`qemu-matrix.yml`, `release-smoke.yml`, `fuzz.yml`)
- Live-network runtime installs and legacy QEMU guest runs remain available via nightly `schedule` or explicit `workflow_dispatch` (`run-qemu=true` in `ci.yml`), preventing upstream CDN outages or VM boot flakes from blocking PR merges.

### Tier 4 — Release & Supply-Chain Integrity (`release.yml`)
- Signed release artifacts, checksum verification, and release smoke checks gated on verified `main` CI.

## Build Speed, Deduplication & Cloudflare R2 Strategy

To overcome Rust compile times across 219k lines of source and multiple distro targets:
1. **Dedicated `[profile.ci]` (`Cargo.toml`):** Uses `debug = "line-tables-only"` (cuts DWARF object size and link latency while preserving full file/line backtraces), `incremental = false` (maximizes `sccache` reuse), and `opt-level = 0` on dependencies for E2E checks.
2. **Fast Linking & Uncapped Cores:** Removed the hard-coded `jobs = 5` cap in `.cargo/config.toml` and enabled `mold` (`-C link-arg=-fuse-ld=mold`) on Linux container E2E builds.
3. **PR vs. Main LTO Split (`ci.yml`):** Pull requests override release validation builds to `CARGO_PROFILE_RELEASE_LTO=thin` and `CODEGEN_UNITS=16`, while `main`, `merge_group`, and `release.yml` retain full `fat` LTO + `codegen-units = 1`.
4. **Scoped Container Triggers (`distro-e2e.yml`):** PRs only rebuild the 8-target container matrix when native package backends, `doctor.rs`, daemon code, or build definitions change; `push` to `main` and `merge_group` always run the full matrix.
5. **Cloudflare R2 Scaling Roadmap:**
   - **Shared `sccache` on R2 (`omg-ci-compiler-cache`):** Zero-egress distributed compiler caching across `ci.yml` and `distro-e2e.yml`.
   - **Next high-ROI upgrades:** Split the monolithic crate into a Cargo workspace (isolating `pkg-db`, `runtimes`, `daemon`, `cli` so unaffected crates skip recompilation), publish weekly prebuilt CI base images (Rust + `mold` + `sccache` + distro `-dev` headers) to GHCR/R2, and use `cargo nextest archive --archive-file` to compile once and partition tests horizontally.

## Documentation-Backed TDD Workflow

Every new CLI command, flag, JSON output, or protocol change follows this loop:
1. Update the source-of-truth specification in [`docs/cli.md`](cli.md) or [`contracts/`](../contracts/service-api-v1.json).
2. Encode the contract in hermetic tests (`tests/cli_doc_contracts.rs`, `tests/cli_surface.rs`, or local fault-injection unit fixtures).
3. Implement the minimal change and verify locally with `cargo test` before relying on Tier 2 distro containers.

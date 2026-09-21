---
title: Package Management
sidebar_position: 10
description: Search, install, update, and remove packages
---

# Package Management

**Complete Guide to Searching, Installing, and Managing Packages**

OMG has supported backends for Arch, Debian/Ubuntu, Fedora, and macOS, with platform-specific coverage and limitations. AUR support is Arch-specific. Release availability and backend limitations are listed in [installation](./installation.md).

---

## 🎯 Overview

OMG's package management features:

- **Daemon-backed searches** with [artifact-specific benchmark evidence](../benchmarks/README.md)
- **Unified AUR integration** — no separate AUR helper needed — see [AUR Support](./aur.md)
- **Security grading** — source/advisory classification, not a safety certification
- **Policy enforcement** — local configured rules with backend-specific coverage
- **Transaction history** — recorded operations where supported and enabled; rollback has backend and artifact limits

---

## 🔍 Package Search

### Basic Search

```bash
# Search all repositories (official + AUR)
omg search vim

# Limit results
omg search vim --limit 10

# Detailed results with votes/popularity where available
omg search visual-studio-code -d

# Skip community sources, official repos only
omg search --no-aur firefox
```

### Search Performance

Use the [benchmark records](../benchmarks/README.md) for artifact-specific measurements. Query, sources, backend, and cache state must match before comparing timings.

### Fuzzy Matching

OMG uses Nucleo for intelligent fuzzy matching:

```bash
omg search frfx
# Finds: firefox, firefox-developer-edition

omg search vsc
# Finds: visual-studio-code-bin, vscodium-bin
```

---

## 📦 Package Installation

### Install Packages

```bash
# Install single package
omg install firefox

# Install multiple packages
omg install firefox chromium brave-bin

# Install AUR package (auto-detected)
omg install visual-studio-code-bin

# Install a package (dependency marking is handled by the backend)
omg install libfoo
```

### Installation Lifecycle

1. **Security Analysis**: Every package is evaluated against the system's security criteria and assigned a grade.
2. **Policy Validation**: The system checks the package against defined rules, ensuring it meets organizational or user-set standards.
3. **Conflict Resolution**: Dependencies are mapped and resolved, ensuring that all required components are available.
4. **Download & Integrity**: Artifacts are retrieved over secure channels and verified using cryptographic signatures and hashes.
5. **Integration**: Official packages are integrated through the system backend, while custom sources are prepared and deployed efficiently.
6. **Audit Recording**: The entire transaction is logged to the history database for future reference or rollback.

### AUR Build Options

Configure in `~/.config/omg/config.toml`:

```toml
[aur]
# Parallel build jobs
build_concurrency = 8

# makepkg flags
makeflags = "-j8"

# Cache built packages
cache_builds = true

# Use ccache for C/C++
enable_ccache = true

# Use sccache for Rust
enable_sccache = false
```

---

## 🗑️ Package Removal

### Remove Packages

```bash
# Remove single package
omg remove firefox

# Remove with orphaned dependencies
omg remove firefox -r  # Arch backend only

# Remove multiple packages
omg remove pkg1 pkg2 pkg3
```

### Safety Features

- Confirms before removing packages
- Won't remove system dependencies
- Warns about dependent packages

---

## 🔄 System Updates

### Update Packages

```bash
# Update everything (official + AUR)
omg update

# Check for updates without installing
omg update --check
```

### Update Flow

1. **Database Sync** — Fresh package lists
2. **Official Updates** — Via pacman
3. **AUR Updates** — Parallel builds
4. **History Recording** — All changes logged

### Selective Updates

```bash
# Update specific package
omg install firefox  # Re-installing updates if newer

# Update official only (traditional pacman)
sudo pacman -Syu
```

---

## ℹ️ Package Information

### Get Package Details

```bash
omg info firefox
```

**Output includes:**

- Name and version
- Description
- Repository (official/AUR)
- Dependencies and optional dependencies
- Installed files count
- Security grade
- Installation status

### Performance

Info-query timings depend on backend, cache state, and remote metadata. Search benchmarks do not establish info-query latency.

---

## 📋 Package Listings

### Explicitly Installed Packages

```bash
# List all explicit packages
omg explicit

# Count only
omg explicit --count
```

### System Status

```bash
omg status
```

Shows:

- Total packages
- Explicit packages
- Orphaned packages
- Updates available
- Vulnerabilities

---

## 🧹 Cleanup

### Clean Caches

```bash
# Remove orphaned packages
omg clean --orphans

# Clear package cache
omg clean --cache

# Clear AUR build cache
omg clean --aur

# Full cleanup
omg clean --all
```

### Sync Databases

```bash
omg sync
```

---

## 🔐 Security Features

### Security Grades

Policy grades describe classification, not a guarantee of package safety or an independent signature receipt. Core package names do not establish SLSA provenance. See [security grades](./security.md#security-grades):

| Grade | Meaning | Examples |
| ------- | --------- | ---------- |
| **LOCKED** | Policy enum value, not an established SLSA level | Not assigned by current source classification |
| **VERIFIED** | Official repository source classification | Official repo packages |
| **COMMUNITY** | AUR/unsigned | AUR packages |
| **RISK** | Known vulnerabilities | CVE-affected packages |

### Policy Enforcement

Create `~/.config/omg/policy.toml`:

```toml
# Minimum grade required
minimum_grade = "Verified"

# Allow AUR packages
allow_aur = true

# Require PGP signatures
require_pgp = false

# Allowed licenses (SPDX)
allowed_licenses = ["Apache-2.0", "MIT"]

# Banned packages
banned_packages = ["some-bad-pkg"]
```

### Vulnerability Checking

OMG checks installed packages against:

- **Arch Linux Security Advisory (ALSA)**
- **OSV.dev global database**

Run audit:

```bash
omg audit
```

---

## 📜 Transaction History

### View History

```bash
# Recent transactions
omg history

# Last 5 transactions
omg history --limit 5
```

### Rollback

```bash
# Interactive rollback
omg rollback

# Rollback specific transaction
omg rollback <transaction-id>
```

**Rollback Constraints:**

- Official packages restore from package cache; AUR packages rebuild from recorded git commits
- Requires cached archives or accessible remote sources
- May have dependency conflicts if system libraries have changed

---

## 🌐 Mirror Management

### Pacman Mirrors

OMG uses system pacman mirrors. Configure in `/etc/pacman.d/mirrorlist`.

### AUR Source

Default AUR endpoint: `https://aur.archlinux.org`

---

## 💨 Performance Tips

### 1. Use the Daemon

```bash
# Start daemon for cache
omg daemon

# Verify it's running
omg status
```

### 2. Use prompt counters in scripts

```bash
# Ultra-fast package count
omg ec  # Explicit count
omg tc  # Total count
```

### 3. Batch Operations

```bash
# Install multiple at once
omg install pkg1 pkg2 pkg3

# Rather than individual commands
omg install pkg1
omg install pkg2
omg install pkg3
```

---

## 🐧 Platform Support

### Backend and release matrix

| Host or backend | Build feature | Package source | Documented coverage and limits |
| --- | --- | --- | --- |
| Arch Linux | `arch` (the default) | libalpm plus the AUR | The broadest package surface, including AUR build, review, policy, and rollback workflows. |
| Debian or Ubuntu | `debian` | Native APT database and packages | Native APT operations; no AUR. Build with `libapt-pkg-dev`, `clang`, `cmake`, `pkg-config`, and OpenSSL development headers. |
| Fedora | `fedora` | DNF/RPM | RPM database reads and DNF-backed operations. Fedora release evidence does not establish compatibility with every RHEL derivative. |
| Apple Silicon macOS | `macos` | Homebrew | Homebrew-backed package operations. The published macOS release is ARM64; Intel macOS is not a supported release target. |
| Debian index/test build | `debian-pure` | Pure-Rust Debian index | Read/index fixtures only. It refuses live Debian/Ubuntu mutations; use the `debian` APT-backed build for a real machine. |
| Windows | none | none | Native Windows has no backend or release. Use a supported Linux distribution inside WSL; WSL uses that guest's backend. |

Published Linux archives are x86_64 and backend-specific. The published macOS archive is Apple Silicon ARM64. Linux ARM64 builds are staged test artifacts rather than published release archives. Runtime managers also have provider-specific host limits, so a package backend being available does not guarantee identical runtime or audit coverage.

Build a backend explicitly from a reviewed checkout:

```bash
cargo build --release --locked --no-default-features --features arch,pgp,license
cargo build --release --locked --no-default-features --features debian,pgp,license
cargo build --release --locked --no-default-features --features fedora,pgp,license
cargo build --release --locked --no-default-features --features macos,pgp,license
# Index/test fixtures only; this build refuses live Debian/Ubuntu mutations.
cargo build --release --locked --no-default-features --features debian-pure,pgp,license
```

Cargo features are additive; `--features debian` does not remove the default Arch backend unless `--no-default-features` is also supplied. `debian-pure` is not a live package backend and must not be used as a release build. The optional `license` feature gates only the `omg account` subcommand. See [installation](./installation.md) for system prerequisites and release artifact provenance.

---

## 🔧 Troubleshooting

### Search Returns Nothing

```bash
# Sync databases
omg sync

# Restart daemon
pkill omgd && omg daemon

# Try direct
pacman -Ss <query>
```

### AUR Build Fails

```bash
# Check base-devel
pacman -Q base-devel

# Clear cache and retry
omg clean --aur
omg install <package>

# Check logs
cat ~/.cache/omg/logs/*.log
```

### Permission Denied

```bash
# AUR builds shouldn't need sudo
# Official installs prompt for sudo

# If socket issues
ls -la $XDG_RUNTIME_DIR/omg.sock
```

---

## 📚 See Also

- [CLI Reference](./cli.md) — All package commands
- [Security & Compliance](./security.md) — Security grading details
- [Configuration](./configuration.md) — Policy configuration
- [History & Rollback](./history.md) — Transaction management
- [Integrations](./integrations.md) — Using OMG with fzf, ripgrep, and other tools
- [Troubleshooting](./troubleshooting.md) — Common package management issues

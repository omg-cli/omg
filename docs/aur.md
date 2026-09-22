# AUR Support

**In plain words:** The AUR is a collection of build instructions written by Arch Linux users rather than by the distribution. This page explains how OMG reviews and builds those packages, and which safety choices you are making.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG supports the Arch User Repository (AUR) with the same install, search, and update commands used for official packages.

## Overview

OMG treats AUR packages as first-class citizens, with no distinction between official repository packages and AUR packages in the CLI. Just use `omg install` for everything.

**Key advantages over yay/paru:**

- **One command surface** for official and AUR packages
- **No sudo timeouts** during long builds
- **Parallel source downloads** for multi-source packages
- **Smart dependency resolution** that skips unnecessary API calls
- **Real-time progress tracking** for downloads and installations
- **Offline Bubblewrap builds** with a cleared environment and private home
- **Sealed artifact handoff** between review, build, and privileged installation
- **Static archive inspection** before the package database is changed
- **Independent exact rebuilds** for packages that integrate with privileged system surfaces

## Security model

Run OMG as your regular user. Do not use `sudo omg`. OMG requests sudo only when a validated package transaction must change the system package database. Direct root execution remains compatible for now but is deprecated, and AUR builds are always refused when OMG starts as root.

Arch's packaging documentation states that a PKGBUILD is directly sourced and executed by `makepkg`, while a package-specific install script can run before or after installation, upgrade, and removal. OMG therefore treats both the recipe and its output archive as executable input. See the [PKGBUILD format and execution model](https://man.archlinux.org/man/PKGBUILD.5) and [install-script lifecycle](https://man.archlinux.org/man/PKGBUILD.5#INSTALL/UPGRADE/REMOVE_SCRIPTING).

The default AUR path uses five gates:

1. Sources are fetched without executing the PKGBUILD.
2. The complete source tree is reviewed, hashed, and rechecked before an offline Bubblewrap build. Bubblewrap itself is a policy-building tool, so OMG supplies the filesystem, network, session, and privilege restrictions described by its [upstream security model](https://github.com/containers/bubblewrap/blob/main/README.md#sandbox-security).
3. Every output is parsed without extraction. OMG rejects traversal, duplicate paths, special device/FIFO/socket entries, escaping links, inconsistent `.PKGINFO`/`.BUILDINFO`, undeclared or changed `.INSTALL` hooks, and malformed metadata.
4. Archives containing install hooks, privilege-bearing files, systemd units, kernel modules, package-manager hooks, privileged service integration, or `/etc` payloads are rebuilt in a second private invocation. Both builds receive the same source-derived [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/), which [makepkg uses to unify source/package timestamps and package metadata](https://man.archlinux.org/man/makepkg.8#REPRODUCIBILITY), and every output must match byte-for-byte. This follows the Reproducible Builds guidance to perform independent builds and [compare their results](https://reproducible-builds.org/docs/plans/). Ordinary packages keep the single-build path. Successful comparisons are cached only in process memory and are keyed by the reviewed source, build policy, build environment, and exact output hashes.
5. The accepted bytes are copied into a sealed Linux memfd. The root transaction accepts only that handoff and reinspects the staged bytes. Linux documents file seals as protection against shared-memory modification and TOCTOU races in [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html).

An archive containing `.INSTALL`, setuid/setgid files, or file capabilities requires a separate attended confirmation. `--yes` does not answer this prompt, and unattended execution fails before that archive's installation transaction requests sudo. Linux explains the authority carried by these capability mechanisms in [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html).

Each accepted archive records its source-manifest SHA-256, archive SHA-256, inspection-policy version, package identity, hook hash, privileged-file count, and approval outcome in OMG's bounded audit chain. These hashes are correlation and tamper-detection evidence; they do not turn an untrusted AUR recipe into a trusted publisher signature. Arch documents publisher-controlled source verification through `validpgpkeys` and full fingerprints in the [PKGBUILD integrity fields](https://man.archlinux.org/man/PKGBUILD.5#INTEGRITY).

## Performance Features

### 1. Parallel Source Downloads

When building AUR packages with multiple sources, OMG downloads them all concurrently instead of sequentially.

**Impact**: Total download time approaches the slowest single source instead of the sum.

### 2. Smart Dependency Resolution

Before querying the AUR API for dependencies, OMG filters out packages already installed on your system.

**Impact**: Eliminates unnecessary network calls for packages with many deps.

### 3. Sudoloop Mechanism

OMG automatically maintains sudo authentication throughout the entire build process via a background refresh thread.

**Impact**: No more password prompts mid-build. Critical for packages with long compilation times (e.g., `chromium`, `linux`).

### 4. Metadata Archive

Bulk update checks use the AUR metadata archive instead of one request per package.

**Impact**: Fewer API calls and faster update discovery across many AUR packages.

### 5. Streamlined Build Process

Unnecessary intermediate cleanup steps have been removed, and cleanup only occurs when actually needed.

**Impact**: Reduces overhead and I/O operations during builds.

### 6. Real-time Progress Tracking

Live progress indicators show exactly what's downloading, building, and installing.

**Impact**: Better user experience and visibility into what OMG is doing.

## Configuration

Add these to your `~/.config/omg/config.toml`:

```toml
[aur]
# Build isolation (default: "bubblewrap"); "chroot" or "native"
build_method = "bubblewrap"

# Maximum concurrent AUR builds (default: 1)
build_concurrency = 4

# Require interactive PKGBUILD review before building (default: true)
review_pkgbuild = true

# Never expose host networking to package build code (default: false)
allow_network = false

# Native builds require this explicit unsafe compatibility opt-in (default: false)
allow_unsafe_builds = false
```

Review is fail-closed: with review enabled and no interactive terminal,
both single-package and parallel builds bail before cloning or building.
The `--review` flag forces review for one invocation. Disabling review does not disable archive inspection, sealed handoff, or exceptional-privilege rejection.

## Usage Examples

```bash
# Install an AUR package (just like pacman/yay)
omg install yay

# Install with dependencies
omg install spotify

# Search AUR and official repos together
omg search chrome

# Update all packages (official + AUR)
omg update

# Remove an AUR package
omg remove spotify
```

## Benchmarks

Reproducible measurements live in `benchmarks/records/` (search, info, status, and explicit operations). AUR install times depend on network speed, CPU, and package complexity, so they are not published as fixed numbers.

## How It Works

When you run `omg install <aur-package>`:

1. **Query AUR API** for package metadata
2. **Smart dependency check**: Filter already-installed deps from the list
3. **Clone git repo** to build directory
4. **Start sudoloop** in background to maintain authentication
5. **Parse PKGBUILD** using cached regex patterns
6. **Download sources in parallel** via tokio async runtime
7. **Build package** with makepkg
8. **Inspect and seal outputs** without extracting them to the host
9. **Approve exceptional privileges** when a hook, capability, or set-ID file exists
10. **Install through the constrained root transaction** using maintained sudo credentials

## Troubleshooting

### Sudo timeout during builds

OMG refreshes sudo authentication automatically during builds. If a prompt still appears, run `omg doctor` to diagnose privilege issues.

### Slow builds

Raise the concurrent build limit:

```toml
[aur]
build_concurrency = 8  # Build up to 8 packages concurrently
```

### Build failures

Point `pkgdest` and `srcdest` at known locations so outputs survive for inspection:

```toml
[aur]
pkgdest = "/var/cache/omg/packages"
srcdest = "/var/cache/omg/sources"
```

## Comparison with yay/paru

| Feature | OMG | yay | paru |
| --------- | ----- | ----- | ------ |
| Parallel downloads | ✅ Yes | ❌ No | ❌ No |
| Smart dep resolution | ✅ Yes | ❌ No | ❌ No |
| Sudoloop | ✅ Yes | ❌ No | ⚠️ Partial |
| Progress tracking | ✅ Real-time | ⚠️ Basic | ⚠️ Basic |
| Build cache reuse | ✅ Yes | ❌ No | ❌ No |

## Technical Details

### Parallel Download Implementation

OMG uses Rust's async runtime (tokio) to spawn concurrent download tasks:

```rust
// Pseudo-code representation
let handles: Vec<_> = sources
    .iter()
    .map(|src| tokio::spawn(download(src)))
    .collect();

for handle in handles {
    handle.await?;
}
```

### Sudoloop Architecture

A dedicated background thread spawns `sudo -v` every N seconds:

```rust
thread::spawn(move || {
    loop {
        Command::new("sudo").arg("-v").output().ok();
        thread::sleep(Duration::from_secs(refresh_interval));
    }
});
```

### Smart Dependency Filtering

Before querying AUR:

```rust
let installed = get_installed_packages();
let deps_to_fetch: Vec<_> = deps
    .iter()
    .filter(|d| !installed.contains(d))
    .collect();
```

This simple optimization can eliminate 50%+ of AUR API calls for packages with many common dependencies.

## Contributing

Found a way to make AUR support even faster? Open an issue or PR!

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

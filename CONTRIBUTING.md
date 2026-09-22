# Contributing to OMG

Start with a reproducible bug, a focused improvement, or a documentation correction. Keep unrelated changes separate and report the exact checks you ran.

---

## 🚀 Quick Start

### Prerequisites

- **Rust:** 1.95.0 or later (uses Rust Edition 2024, see `rust-toolchain.toml`)
- **Platform-specific dependencies:**
  - **Arch Linux:** `base-devel`, `libalpm` (installed by default)
  - **Debian/Ubuntu:** `build-essential`, `libapt-pkg-dev`
  - **macOS:** Xcode Command Line Tools
  - **WSL:** Use the prerequisites for the installed Linux distribution; native Windows development is unsupported

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/omg-cli/omg.git
cd omg

# Check your toolchain meets MSRV 1.95.0
rustc --version

# Build the project
cargo build --locked --no-default-features --features arch,pgp,license

make ci-local-quick
cargo fmt
```

Choose the backend for your host from the release feature matrix below. Cargo features are additive; selecting `debian`, `fedora`, or `macos` without `--no-default-features` also retains the default Arch backend. Test package mutations in disposable containers or VMs, not on the development host.

### Running OMG Locally

```bash
# Run the CLI (debug build)
cargo run --features arch --bin omg -- search firefox

# Run the daemon
cargo run --features arch --bin omgd

# Run with release optimizations
cargo build --release --features arch
./target/release/omg search firefox
```

---

## 🏗️ Project Structure

```
omg/
├── src/
│   ├── bin/
│   │   ├── omg.rs          # CLI entry point
│   │   └── omgd.rs         # Daemon entry point
│   ├── cli/
│   │   ├── args.rs         # Argument parsing (clap)
│   │   └── commands.rs     # Command implementations
│   ├── core/
│   │   ├── types.rs        # Shared types
│   │   ├── error.rs        # Error handling
│   │   ├── client.rs       # Daemon IPC client
│   │   ├── http.rs         # HTTP client utilities
│   │   └── paths.rs        # Path helpers
│   ├── daemon/
│   │   ├── server.rs       # Unix socket server
│   │   └── cache.rs        # LRU cache
│   ├── package_managers/
│   │   ├── traits.rs       # PackageManager trait
│   │   ├── arch.rs         # pacman/libalpm
│   │   ├── alpm_ops.rs     # Direct ALPM operations
│   │   ├── aur.rs          # AUR client
│   │   ├── debian.rs       # APT integration
│   │   ├── dnf.rs          # RPM/DNF integration
│   │   ├── homebrew.rs     # macOS Homebrew integration
│   │   └── types.rs        # Package types
│   ├── runtimes/
│   │   ├── node.rs         # Node.js/npm
│   │   ├── python.rs       # Python/pip
│   │   ├── go.rs           # Go modules
│   │   ├── rust.rs         # Cargo
│   │   ├── ruby.rs         # Gems
│   │   ├── java.rs         # Maven/Gradle
│   │   ├── bun.rs          # Bun runtime
│   │   ├── pi.rs           # Pi runtime
│   │   ├── deno.rs         # Deno runtime
│   │   ├── zig.rs          # Zig toolchain
│   │   ├── dotnet.rs       # .NET SDK
│   │   ├── erlang.rs       # Erlang/OTP
│   │   ├── php.rs          # PHP runtime
│   │   └── swift.rs        # Swift toolchain
│   └── config/
│       └── settings.rs     # Configuration
├── tests/                  # Integration tests
├── docs/                   # Documentation
└── scripts/                # Build/benchmark scripts
```

---

## 📝 Code Style Guidelines

### Rust Edition & Version

- **Edition:** `2024` (latest stable Rust edition)
- **MSRV:** `1.95.0+` (matches `rust-version` in `Cargo.toml`)
- **Target:** Follow Rust 2024 idioms and zero-cost abstractions

### Formatting

We use `rustfmt` with default settings:

```bash
# Format all code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check
```

### Linting

Run the checks that match the GitHub workflow:

Use this target while editing:

```bash
make ci-local-quick
```

Use this target before pushing:

```bash
make ci-local-full
```

Both targets use Rust 1.95.0, locked dependencies, and build output under `~/.cache/build-targets/omg-ci-local`. The full target checks the portable, `debian-pure`, and Arch feature sets. It also runs all hermetic Arch tests. GitHub runs the native Debian, Fedora, Ubuntu, macOS, Docker, coverage, and CodeQL jobs.

GitHub's Quick Gate invokes the quick target once; do not repeat its formatting, script tests, shell syntax, or fuzz compile steps in dependent jobs. Portable retains Clippy and library tests. The Linux Arch lane covers `arch,pgp,license`; the separate Debian intersection checks `debian,pgp` without license support. Instrumented coverage remains a distinct run, with its reports generated from the same captured results.

Do not run `cargo clippy --all-targets --all-features` on Arch. That command enables incompatible native package-manager bindings.

**Key clippy rules we follow:**
- Deny warnings in CI: code must compile warning-free under target platform features
- No `.unwrap()` in production code (use `.expect()` with context or `?`)
- Prefer `Arc` over `Clone` for large types in async contexts
- Use `Cow<str>` for conditional ownership

### Code Conventions

#### Imports

Order imports: `std::` → external crates → `crate::`/`super::`

```rust
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::core::{Package, PackageSource};
use super::types::PackageManager;
```

#### Error Handling

- **Application code:** Use `anyhow::Result`
- **Library APIs:** Use `thiserror` for custom error types
- **Context:** Always add `.context()` or `.with_context()` for errors

```rust
use anyhow::{Context, Result};

fn load_config(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;
    
    toml::from_str(&content)
        .context("Invalid TOML syntax in config file")
}
```

#### Async Patterns

- Use `tokio` async runtime
- Use `async_trait` for async trait methods
- Prefer `tokio::join!` for parallel operations

```rust
use async_trait::async_trait;

#[async_trait]
pub trait PackageManager: Send + Sync {
    async fn search(&self, query: &str) -> Result<Vec<Package>>;
    async fn install(&self, package: &str) -> Result<()>;
}
```

#### Performance Patterns

**Arc over Clone in async contexts:**

```rust
// ✅ Good: Arc for cheap refcounts
let path = Arc::new(PathBuf::from("/usr/bin"));
tokio::task::spawn_blocking(move || {
    process_path(&path)
});

// ❌ Bad: Expensive heap allocation
let path = PathBuf::from("/usr/bin");
tokio::task::spawn_blocking(move || {
    process_path(&path) // Clones PathBuf
});
```

**Cow for conditional ownership:**

```rust
// ✅ Good: Zero-copy when possible
fn display_path(path: &Path) -> Cow<str> {
    path.to_string_lossy()
}

// ❌ Bad: Always allocates
fn display_path(path: &Path) -> String {
    path.to_string_lossy().to_string()
}
```

**Inline hot-path functions:**

```rust
#[inline]
pub fn shared_client() -> &'static Client {
    &HTTP_CLIENT
}
```

---

## 🧪 Testing

### Running Tests

```bash
# Run all tests
cargo test --features arch

# Run specific test
cargo test --features arch test_validate_build_concurrency

# Run tests in a module
cargo test --features arch core::fast_status::tests

# Show test output
cargo test --features arch -- --nocapture

# Run only unit tests (skip integration)
cargo test --features arch --lib
```

### Writing Tests

**Unit tests** (within module):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_validate_build_concurrency() {
        assert!(validate_build_concurrency(1).is_ok());
        assert!(validate_build_concurrency(8).is_ok());
        assert!(validate_build_concurrency(0).is_err());
    }

    #[tokio::test]
    async fn test_async_search() {
        let manager = ArchPackageManager::new().await.unwrap();
        let results = manager.search("firefox").await.unwrap();
        assert!(!results.is_empty());
    }
}
```

**Integration tests** (`tests/` directory):

```rust
// tests/cli_integration.rs
use assert_cmd::Command;

#[test]
fn test_cli_search() {
    let mut cmd = Command::cargo_bin("omg").unwrap();
    cmd.arg("search")
       .arg("firefox")
       .assert()
       .success();
}
```

### Test Coverage

We aim for high test coverage on critical paths:

```bash
# Generate coverage report (requires cargo-tarpaulin)
cargo tarpaulin --features arch --out Html
```

---

## 🔍 Benchmarking

### Running Benchmarks

```bash
# Quick benchmark (10 runs)
./benchmark-hyperfine.sh --fast

# Full benchmark (400+ iterations)
./benchmark-hyperfine.sh

# Check for performance regressions
python3 scripts/check-perf-regression.py
```

### Performance Targets

- **Search:** < 10ms (median)
- **Info:** < 10ms (median)
- **Status:** < 10ms
- **Daemon startup:** < 100ms
- **Memory usage:** < 50MB (resident)

**Before optimizing:**

1. Profile first (`cargo flamegraph`)
2. Benchmark baseline
3. Apply optimization
4. Measure improvement
5. Document in commit message

---

## 🎯 Pull Request Process

### Before Submitting

1. **Run the local gate:**

   ```bash
   make ci-local-full
   ```

2. **Update documentation** if you:
   - Add/change CLI commands
   - Modify configuration options
   - Change public APIs

3. **Add tests** for:
   - New features
   - Bug fixes
   - Edge cases

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**

- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `refactor`: Code refactoring (no behavior change)
- `docs`: Documentation only
- `test`: Adding/updating tests
- `chore`: Build scripts, dependencies, etc.

**Examples:**

```
feat(aur): add parallel download support

Implements parallel AUR package downloads using tokio::spawn.
Reduces install time by 50% for multi-package operations.

Closes #123
```

```
perf(core): replace PathBuf with Arc in spawn_blocking

Eliminates expensive heap allocations in async contexts.
Measured 7-15% performance gain in search operations.
```

```
fix(daemon): handle SIGTERM gracefully

Ensures in-memory cache flushes to disk before shutdown.
Prevents data loss during system restarts.
```

### PR Description Template

```markdown
## Description
Brief description of what this PR does.

## Motivation
Why is this change needed? What problem does it solve?

## Changes
- List of changes
- Another change

## Testing
How did you test this? What scenarios are covered?

## Performance Impact
Any performance improvements/regressions? Include benchmark results if applicable.

## Breaking Changes
List any breaking changes and migration guide.

## Checklist
- [ ] Local gate passes (`make ci-local-full`)
- [ ] GitHub platform jobs pass
- [ ] Documentation updated (if needed)
- [ ] Benchmarks run (if performance-related)
```

### Review Process

1. **Automated checks** run on PR submission (CI)
2. **Code review** by maintainers (usually within 2-3 days)
3. **Address feedback** with follow-up commits
4. **Squash & merge** once approved

---

## 🐛 Reporting Bugs

### Bug Report Template

```markdown
**Describe the bug**
Clear description of what went wrong.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened.

**Environment:**
- OS: [e.g., Arch Linux]
- OMG version: [e.g., 0.1.204]
- Rust version: [e.g., 1.95.0 (`rustc --version`)]

**Logs**
```

Paste relevant logs here (use --verbose flag)

```

**Additional context**
Any other relevant information.
```

### Feature Requests

Use the GitHub Issues "Feature Request" template. Include:

- **Use case:** Why do you need this?
- **Proposed solution:** How should it work?
- **Alternatives:** What other approaches did you consider?

---

## 🔐 Security Policy

If you discover a **security vulnerability**, please:

1. **Do NOT** open a public issue
2. Email: **<olen@latham.cloud>** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within **48 hours** and will credit you in release notes (unless you prefer to remain anonymous).

---

## 📚 Documentation

Documentation lives in `docs/`:

- **User guides:** `docs/*.md`
- **API docs:** Inline `///` rustdoc comments
- **Architecture:** `AGENTS.md` (for AI agents working on codebase)
- **AI policy precedence:** `AGENTS.md` "AI Instruction Governance (Canonical)"

**Updating docs:**

```bash
# Generate API documentation
cargo doc --no-deps --features arch --open

# Check for broken links (requires lychee)
lychee docs/**/*.md
```

---

## 🤝 Getting Help

- **GitHub Discussions:** For questions and community support
- **GitHub Issues:** For bug reports and feature requests
- **Discord:** (Coming soon)

---

## 📜 License

By contributing, you agree that your contributions will be licensed under the **MIT** license.

See [LICENSE](LICENSE) for details.

---

## 🙏 Thank You

Every contribution makes OMG better. Whether it's code, documentation, bug reports, or feature ideas—we appreciate your help.

**Happy coding!** 🚀

---

## 📦 Dependency & Feature Policy

### Version pinning

- **crates.io dependencies** use caret requirements (`"1.2.3"`). The committed
  `Cargo.lock` is the reproducibility authority — CI builds with `--locked`.
  Bump version *ranges* deliberately and review lockfile diffs for unexpected
  duplicate major versions, new proc macros, or new build scripts.
- **archlinux/alpm git family** (`alpm-types`, `alpm-srcinfo`, `alpm-db`,
  `alpm-repo-db`, `alpm-pkginfo`) is pinned by exact version (`=`) **and**
  full commit `rev` for supply-chain integrity. Updates require a deliberate
  rev bump applied to **all five entries together** (they come from the same
  repo commit), plus a lockfile review.
- **sequoia-openpgp** tracks the stable 2.x line with `allow-experimental-crypto`.
  This is acceptable because OMG uses it only for public-key **signature
  verification**, never private-key decryption.
- The MSRV is pinned in `rust-toolchain.toml`, `package.rust-version`, and CI;
  all three must move together.

### Release feature matrix (product decision)

Release binaries are built with these feature sets (`.github/workflows/release.yml`):

| Target | Features |
| --- | --- |
| Arch | `arch,pgp,license` |
| Fedora | `fedora,pgp,license` |
| macOS ARM64 | `macos,pgp,license` |
| Debian/Ubuntu | `debian,pgp,license` |

Every release build passes `--no-default-features` and `--locked`. Linux
release targets are x86_64. The workflow publishes tar archives, not `.deb`
packages. The `license` Cargo feature compiles the optional `omg account`
dashboard-link command; it is not a local CLI paywall. Review dependency
licenses separately from feature names. Keep the release and CI matrices
consistent when changing shipped features.

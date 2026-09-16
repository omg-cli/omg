---
title: CLI Reference
sidebar_position: 3
description: Complete command reference for all OMG commands
---

# CLI Reference

**Complete Command Reference for OMG**

This guide documents every OMG command with detailed explanations, examples, and use cases. Commands are organized by category.

---

## 📋 Command Overview

| Category | Commands |
| ---------- | ---------- |
| **Package Management** | `search`, `install`, `remove`, `update`, `info`, `clean`, `explicit`, `sync`, `why`, `outdated`, `size`, `blame` |
| **Runtime Management** | `use`, `list`, `which` |
| **Shell Integration** | `hook`, `completions`, `hooks`, `workspace` |
| **Security & Audit** | `audit`, `status`, `doctor` |
| **Task Runner** | `run` |
| **Project Management** | `new`, `tool`, `init`, `self-update` (alias: `up`) |
| **Environment & Snapshots** | `env`, `snapshot`, `diff` |
| **Team Collaboration** | `team`, `privacy` |
| **Container Management** | `container` |
| **CI/CD & Migration** | `ci`, `migrate` |
| **History & Rollback** | `history`, `rollback` |
| **Dashboard** | `dash` (alias: `d`), `stats`, `metrics`, `daemon-status` |
| **Configuration** | `config`, `daemon`, `account`, `generate-man` |
| **Enterprise** | `fleet`, `enterprise` |

> The parser accepts global flags (`-v`/`--verbose`, `-q`/`--quiet`, `--json`, `--all-commands`), but individual commands and early fast paths need not implement every output mode. Do not assume a stable JSON schema without checking that command. `omg --help` hides advanced commands unless `--all-commands` is passed. See [🌍 Global Options](#-global-options).

---

## 📦 Package Management

### omg search

Search for packages across official repositories and AUR.

```bash
omg search <query> [OPTIONS] [aliases: s]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--detailed` | `-d` | Show detailed source metadata (votes, popularity where available) |
| `--no-aur` | | Search official repositories only (skip community sources) |
| `--limit <LIMIT>` | `-l` | Maximum number of results to display (default: 15) |

**Examples:**

```bash
# Basic search
omg search firefox

# Detailed search with AUR votes/popularity
omg search spotify -d

# Limit results
omg search node --limit 10
```

**Performance:**

Latency depends on the backend, cache state, query, and enabled sources. See [benchmark scope and records](../benchmarks/README.md).

---

### omg install

Install packages from official repositories or AUR.

```bash
omg install [packages...] [OPTIONS] [aliases: i]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--yes` | `-y` | Skip confirmation prompt |
| `--dry-run` | | Show what would be installed without making changes |
| `--review` | | Force PKGBUILD review for each AUR build (on by default; see `aur.review_pkgbuild`) |
| `--allow-local-file` | | Explicitly permit installation from local package archives |

**Examples:**

```bash
# Search interactively without knowing the exact name
omg install

# Search and preview without installing
omg install --dry-run

# Install single package
omg install neovim

# Install multiple packages
omg install firefox chromium brave-bin

# Install AUR package
omg install visual-studio-code-bin

# Skip confirmation
omg install neovim -y
```

With no package arguments, an interactive terminal opens a fuzzy package picker.
Type to filter, use Up/Down to highlight a package, and press Enter to select it.
Escape or Ctrl-C cancels without installing. Selection uses the normal confirmation
and security checks; `--yes` skips confirmation but never selects a package for you.
Without a terminal, package names are required.

The picker and shell completion use the complete local package-name catalog plus
available AUR names. AUR names are cached for 24 hours; a cache miss may fetch the
index with a bounded network timeout. If AUR is unavailable, local names remain
available. Neither discovery path synchronizes package databases or installs packages.

After [setting up shell completion](shell-integration.md),
try `omg install frfx<Tab>`. Package completion also works after `-y`, additional
package names, and the `i` alias.

**Security:**

- Packages are graded (LOCKED, VERIFIED, COMMUNITY, RISK)
- Policy enforcement applied before installation
- PGP signatures verified for official packages

---

### omg remove

Remove installed packages.

```bash
omg remove <packages...> [OPTIONS] [aliases: r]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--recursive` | `-r` | Also remove unused dependencies |
| `--yes` | `-y` | Skip confirmation prompt |
| `--dry-run` | | Show what would be removed without making changes |

**Examples:**

```bash
# Remove single package
omg remove firefox

# Remove with dependencies
omg remove firefox -r

# Remove multiple packages
omg remove pkg1 pkg2 pkg3
```

---

### omg update

Update all packages or check for updates.

```bash
omg update [OPTIONS] [aliases: u]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--check` | `-c` | Only check for updates, don't install |
| `--yes` | `-y` | Skip confirmation prompt |
| `--dry-run` | | Show what would be updated without making changes |
| `--no-sync` | | Do not refresh sync databases before upgrade |
| `--aur-only` | | Update AUR packages only; skip official database sync and system upgrade (Arch only) |
| `--fast` | `-f` | Fast mode: sync + upgrade in a single operation (no preview) |
| `--turbo` | `-T` | Turbo mode: skip sync, use cached data, parallel extraction |
| `--review` | | Force PKGBUILD review for each AUR build (on by default; see `aur.review_pkgbuild`) |

**Examples:**

```bash
# Update all packages (official + AUR)
omg update

# Check for updates only
omg update --check

# Update AUR packages without touching the official system-update lane
omg update --aur-only

# Fast path without preview
omg update --fast
```

**Update Flow:**

1. Sync package databases
2. Update official packages first
3. Build and update AUR packages
4. Record transaction in history

With `--aur-only`, steps 1 and 2 are omitted. AUR updates still use the normal
policy screening, source review, sandboxed build, package archive inspection,
and sealed privileged-install handoff. The flag cannot be combined with
`--fast` or `--turbo`. PKGBUILD source checksums remain enforced by `makepkg`
unless a recipe explicitly declares `SKIP`; OMG keeps PKGBUILD review enabled
so that exception remains visible rather than being described as verified
content. See the
[PKGBUILD integrity fields](https://man.archlinux.org/man/PKGBUILD.5.en#cksums_(array))
and the [AUR security workflow](aur.md).

---

### omg info

Display detailed package information.

```bash
omg info <package>
```

**Examples:**

```bash
# Get info about a package
omg info firefox

# Get info about AUR package
omg info visual-studio-code-bin
```

**Output includes:**

- Package name and version
- Description
- Repository (official/AUR)
- Dependencies
- Installation status
- Security grade

**Performance:**

See [benchmark evidence](../benchmarks/README.md); timings depend on backend, artifact, sources, and cache state.

---

### omg clean

Clean package caches and remove orphaned packages.

```bash
omg clean [OPTIONS]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--orphans` | `-o` | Remove orphaned packages |
| `--cache` | `-c` | Clear package cache |
| `--aur` | | Clear build directories for source-based installs |
| `--all` | `-a` | Remove all (orphans + cache + aur) |
| `--dry-run` | | Show what would be cleaned without making changes |
| `--yes` | `-y` | Skip confirmation |

**Examples:**

```bash
# Remove orphaned packages
omg clean --orphans

# Clear package cache
omg clean --cache

# Clear AUR build directories
omg clean --aur

# Full cleanup
omg clean --all

# Preview without changing anything
omg clean --dry-run --all

# Non-interactive full cleanup (scripts, CI)
omg clean --all --yes
```

---

### omg explicit

List explicitly installed packages.

```bash
omg explicit [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--count` | `-c` | Only show count |

**Examples:**

```bash
# List all explicit packages
omg explicit

# Get count only
omg explicit --count
```

**Performance:**

Measure this operation on the selected backend with recorded cache conditions; no universal latency is guaranteed.

---

### omg sync

Synchronize package databases.

```bash
omg sync [aliases: sy]
```

**Examples:**

```bash
# Sync databases
omg sync
```

---

### omg why

Explain why a package is installed by showing its dependency chain.

```bash
omg why <package> [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--reverse` | `-r` | Show what depends on this package |

**Examples:**

```bash
# See why a package is installed
omg why libxcb

# See what depends on a package
omg why openssl --reverse
```

**Output includes:**

- Dependency chain from explicit packages
- Whether safe to remove
- Number of dependents

---

### omg outdated

Show packages with available updates.

```bash
omg outdated [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | | Output as JSON |

**Examples:**

```bash
# List all outdated packages
omg outdated

# Machine-readable output
omg outdated --json
```

---

### omg size

Show disk usage by packages.

```bash
omg size [OPTIONS]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--tree <package>` | `-t` | Show dependency tree for package |
| `--limit <N>` | `-l` | Number of packages to show (default: 20) |

**Examples:**

```bash
# Show largest packages
omg size

# Show top 50 packages
omg size --limit 50

# Show dependency tree for a package
omg size --tree firefox
```

---

### omg blame

Show when and why a package was installed.

```bash
omg blame <package>
```

**Examples:**

```bash
# See installation history for a package
omg blame firefox
```

**Output includes:**

- Installation date/time
- Whether installed explicitly or as dependency
- Which package pulled it in (if dependency)
- Transaction ID

---

## 🔧 Runtime Management

### omg use

Install and activate a runtime version.

```bash
omg use <runtime> [version]
```

**Supported Runtimes:**

| Runtime | Aliases | Version Files |
| --------- | --------- | --------------- |
| `node` | `nodejs` | `.nvmrc`, `.node-version` |
| `bun` | `bunjs` | `.bun-version` |
| `python` | `python3` | `.python-version` |
| `go` | `golang` | `.go-version` |
| `rust` | `rustlang` | `rust-toolchain.toml` |
| `ruby` | | `.ruby-version` |
| `java` | | `.java-version` |
| `pi` | | `.tool-versions` |
| `deno` | | `.deno-version`, `.dvmrc` |
| `zig` | `ziglang` | `.zig-version` |
| `dotnet` | | `global.json` |
| `erlang` | | `.tool-versions` |
| `php` | | `.php-version` |
| `swift` | | `.swift-version` |

**Options:**

| Option | Description |
|--------|-------------|
| `--uninstall` | Uninstall the specified version instead of activating it |

Plus 54 GitHub-release tools managed through one generic backend
(`ripgrep`, `fd`, `bat`, `eza`, `fzf`, `starship`, `just`, `task`, `jq`,
`yq`, `gh`, `lazygit`, `delta`, `neovim`, `helix`, `zellij`, `helm`, `k9s`,
`terraform`, `opentofu`, `vault`, `consul`, `minikube`, `kind`,
`kustomize`, `tilt`, `skaffold`, `lazydocker`, `glow`, `pandoc`,
`shellcheck`, `shfmt`, `hadolint`, `actionlint`, `hyperfine`, `tokei`,
`dust`, `duf`, `procs`, `ruff`, `uv`, `fnm`, `protoc`, `terragrunt`,
`packer`, `dive`, `golangci-lint`, `delve`, `stylua`, `kotlin`, `scala`,
`elixir`, `ghcup`) plus the `dotnet` SDK, Erlang/OTP, and PHP managers —
68 registered runtimes/tools in total. Platform availability varies by publisher. Each installs checksum-verified release
assets into `<data-dir>/versions/<tool>/<version>/bin` (flat-layout SDKs
like .NET expose their host binary at the version root instead), so `use`,
`list`, `hook-env`, and version-file detection work exactly like the
language runtimes.

Erlang/OTP installs Hex bob prebuilds on Linux using the archive SHA-256
from `builds.txt`, followed by `./Install -minimal` and an `erl` smoke test.
Older index rows without archive checksums are not installable. It uses
erlef/otp_builds on macOS with SHA-256 from the published CSV; override the
Ubuntu build with `OMG_ERLANG_UBUNTU_RELEASE`. Elixir needs Erlang/OTP on
`PATH` (its prebuilt zips are BEAM bytecode; when a release ships per-OTP
variants OMG picks the lowest for the widest compatibility) — install both
with `omg use erlang` then `omg use elixir`. PHP installs
[shivammathur/php-builder](https://github.com/shivammathur/php-builder)
prebuilts (SHA-256 GitHub asset digests, `php -v` smoke test) on
Debian/Ubuntu; override detection with `OMG_PHP_DISTRO`. Upstream
publishes one rolling build per minor, so versions are channels (`8.5`),
not exact patches — reinstalling refreshes to the latest patch, and
`.php-version` pins work via the phpenv convention. Haskell is covered
through `ghcup`, which installs and manages GHC/cabal/HLS itself. Swift uses
official Ubuntu toolchains with detached-signature verification and a matching
`swift --version` check before publication. Swift installation requires an OMG
build with the `pgp` feature; `.swift-version` pins select `usr/bin`.

**mise compatibility (no mise required):** OMG reads `mise.toml` /
`.mise.toml` `[tools]` pins, `[env]` variables, and `[tasks.*]` entries
natively, so projects already using mise work without installing it.
`[env]` supports plain values, `false` (unset), `{ default = … }`,
`{ value/tools/redact = … }`, `{ required = true }`, top-level
`redactions`, `_.path` (PATH prepend), `_.file` (dotenv/JSON/TOML —
YAML is rejected), `_.source` (evaluated only for explicit `run`/tasks),
`{{env.NAME}}`/`{{config_root}}`
templates, and per-task `env` (including task `_.file`/`_.path`/`_.source`).
Automatic hooks select installed runtimes only. They do not apply project
`[env]` assignments, unsets, files, paths, or scripts: entering a repository
does not authorize changes to the interactive shell's execution environment.
Runtime pin and manifest reads reject symlinks and special files and are
limited to 1 MiB. Invalid pins are reported without blocking the prompt.
`run` and task execution fail closed on missing files and unmet
`required` entries.

Unsupported runtime names fail explicitly.

**Examples:**

```bash
# Install and use Node.js 20
omg use node 20.10.0

# Install and use latest LTS
omg use node lts

# Install Python 3.12
omg use python 3.12.0

# Use Rust stable
omg use rust stable

# Use Rust nightly
omg use rust nightly

# Install and activate an exact Pi release
omg use pi 0.83.0
```

**How It Works:**

1. Checks if version is installed
2. Downloads if not installed
3. Creates/updates `current` symlink
4. Updates PATH via shell hook

---

### omg list

List installed or available runtime versions.

```bash
omg list [runtime] [OPTIONS] [aliases: ls]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--available` | `-a` | Show versions available for download |

**Examples:**

```bash
# List all installed versions for all runtimes
omg list

# List installed Node.js versions
omg list node

# List available Node.js versions
omg list node --available

# List available Python versions
omg list python --available
```

---

### omg which

Show which version of a runtime would be used.

```bash
omg which <runtime>
```

**Examples:**

```bash
# Check active Node.js version
omg which node

# Check active Python version
omg which python

# Check active Rust version
omg which rust
```

**Version Detection Order:**

1. Project-level version file (`.nvmrc`, etc.)
2. Parent directory version files (walking up)
3. Global `current` symlink

---

## 🐚 Shell Integration

### omg hook

Print the shell hook script for runtime auto-switching.

> Not to be confused with [`omg hooks`](#omg-hooks) (Git hooks for environment
> synchronization). The internal `omg hook-env` command is hidden and only
> called by the shell hook on directory change; see
> [Shell Integration](./shell-integration.md).

```bash
omg hook <shell> [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--uninstall` | Remove OMG hooks from shell startup configuration |

**Supported Shells:**

- `zsh`
- `bash`
- `fish`

**Examples:**

```bash
# Get Zsh hook
omg hook zsh

# Add to ~/.zshrc
eval "$(omg hook zsh)"

# Add to ~/.bashrc
eval "$(omg hook bash)"

# Add to ~/.config/fish/config.fish
omg hook fish | source
```

**Hook Features:**

- PATH modification on directory change
- Runtime version detection
- Ultra-fast package count functions

---

### omg completions

Generate shell completion scripts.

```bash
omg completions <shell> [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--stdout` | Print to stdout instead of installing |

**Supported Shells:**

- `zsh`
- `bash`
- `fish`
- `powershell` (alias: `pwsh`)
- `elvish`

**Examples:**

```bash
# Install Zsh completions
omg completions zsh

# Install Bash completions
omg completions bash

# Install Fish completions
omg completions fish

# Output PowerShell completions
omg completions powershell --stdout

# Print a script without installing it
omg completions zsh --stdout > _omg
```

Follow the printed shell setup instructions after installation. See [shell completion setup](shell-integration.md) for Zsh's `fpath` and `compinit` configuration.

---

### omg hooks

Manage Git hooks for environment synchronization.

> Not to be confused with [`omg hook`](#omg-hook) (shell init script printed
> via `eval "$(omg hook zsh)"`).

```bash
omg hooks <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `install [--force]` | Install Git hooks for environment synchronization |
| `uninstall` | Uninstall Git hooks |
| `status` | Show installed hooks status |
| `run <hook>` | Run a specific hook manually (pre-commit, post-checkout, post-merge) |

---

### omg workspace

Workspace management for monorepos.

```bash
omg workspace <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `init <name>` | Initialize a new workspace |
| `add <path> [--name]` | Add a project to the workspace |
| `remove <project>` | Remove a project from the workspace |
| `list` | List all projects in the workspace |
| `run <command> [-p] [--filter] [--yes]` | Run a command across all projects |
| `diff [branch]` | Show environment diff across workspace vs a branch (default: main) |
| `check` | Check all project environments without changing them |
| `status` | Show workspace status |

Running a repo-defined command prompts for confirmation when a terminal is
attached (default No) and refuses without one unless `--yes` is passed.

---

### omg privacy

Manage your privacy settings and data (GDPR/CCPA).

```bash
omg privacy [SUBCOMMAND]
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `status` | Show local privacy settings and the authenticated account-management URL |
| `export [-o <file>]` | Export local OMG data |
| `opt-out` | Disable telemetry collection |
| `opt-in` | Re-enable telemetry collection |

Local exports include archived package history. Each source file is limited to
64 MiB. Larger files cause the export to fail rather than silently omitting or
truncating data. Streaming exports for larger archives are not supported.

---

## 🛡️ Security & Audit

### omg audit

Security audit suite with multiple subcommands.

```bash
omg audit [SUBCOMMAND]
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `scan` | Scan for vulnerabilities (default) |
| `sbom` | Generate installed Arch package CycloneDX 1.5 inventory with advisory matching |
| `secrets` | Scan for leaked credentials |
| `log` | View audit log entries |
| `verify` | Check local hash-chain consistency, not authenticity or completeness |
| `policy` | Show security policy status |
| `slsa <pkg>` | Check supported artifact signatures; requires exact `--certificate-identity`, establishes no SLSA build level |
| `licenses` | Scan for software license compliance issues |
| `fix` | Auto-fix vulnerabilities by upgrading packages |
| `export` | Export compliance evidence for audit frameworks |
| `eol` | Check end-of-life status for installed runtimes |

`scan` requires the Unix daemon and does not fail solely because findings exist. `sbom` always requests Arch advisory matching; it fails on Debian-like systems and lacks a Fedora/macOS system backend. It does not resolve dependency edges. `licenses` and vulnerability auto-fix require the Arch backend.

`omg audit export --framework soc2` requires the daemon and supported SBOM backend. The other accepted framework names return unimplemented errors. `--period` labels the export; it does not filter history. Output is plaintext and can be partial on failure. See [security limits](./security.md).

**Options for `log`:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--limit` | `-l` | Entry limit; defaults to 20 on screen and all entries on export |
| `--severity` | `-s` | Filter by severity (debug, info, warning, error, critical) |
| `--export` | `-e` | Export logs to a file (CSV or JSON) |

**Examples:**

```bash
# Vulnerability scan (default)
omg audit
omg audit scan

# Generate SBOM
omg audit sbom -o sbom.json

# Scan for secrets
omg audit secrets
omg audit secrets -p /path/to/project

# View audit log
omg audit log
omg audit log --limit 50
omg audit log --severity error

# Export audit logs
omg audit log --export audit.csv
omg audit log --export security_report.json

# Verify log integrity
omg audit verify

# Show policy status
omg audit policy

# Check an artifact against an independently trusted signer identity
omg audit slsa ./package.pkg.tar.zst --certificate-identity "$EXPECTED_SIGNER_IDENTITY"
```

---

### omg status

Display system status overview.

```bash
omg status [--fast]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--fast` | `-f` | Use fast path (counts only, skips full dependency scan) |

**Output includes:**

- Package counts (total, explicit, orphans)
- Available updates
- Active runtime versions
- Security vulnerabilities
- Daemon status

---

### omg doctor

Run system health checks.

```bash
omg doctor [OPTIONS]
```

| Option | Description |
| -------- | ------------- |
| `--network` | Test network connectivity to package mirrors |
| `--eol` | Check for end-of-life runtime versions |
| `--turbo` | Prime sudo credentials and remove legacy file capabilities; does not grant capability-based package access |

**Checks performed:**

- PATH configuration
- Shell hook installation
- Daemon connectivity
- Mirror availability
- Package index health (on Debian/Ubuntu, compressed `*_Packages.lz4`/`.gz`/`.xz` indexes count as healthy)
- PGP keyring status
- Runtime integrity

---

## 🏃 Task Runner

### omg run

Run project tasks with automatic runtime detection.

```bash
omg run <task> [-- <args...>] [OPTIONS]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--watch` | `-w` | Watch mode: re-run task on file changes |
| `--parallel` | `-p` | Run multiple comma-separated tasks in parallel |
| `--using <ecosystem>` | `-u` | Ecosystem to use (e.g., node, rust, python, make) |
| `--all` | `-a` | Run task across all detected ecosystems |

**Supported Project Files:**

| File | Runtime | Example |
| ------ | --------- | --------- |
| `package.json` | npm/yarn/pnpm/bun | `omg run dev` → `npm run dev` |
| `deno.json` | deno | `omg run dev` → `deno task dev` |
| `Cargo.toml` | cargo | `omg run test` → `cargo test` |
| `Makefile` | make | `omg run build` → `make build` |
| `Taskfile.yml` | task | `omg run build` → `task build` |
| `pyproject.toml` | poetry | `omg run serve` → `poetry run serve` |
| `Pipfile` | pipenv | `omg run lint` → `pipenv run lint` |
| `composer.json` | composer | `omg run test` → `composer run-script test` |
| `pom.xml` | maven | `omg run test` → `mvn test` |
| `build.gradle` | gradle | `omg run test` → `gradle test` |

**Examples:**

```bash
# Run development server
omg run dev

# Run tests with arguments
omg run test -- --verbose

# Watch mode - re-run on file changes
omg run test --watch

# Run multiple tasks in parallel
omg run build,test,lint --parallel
```

**JavaScript Package Manager Priority:**

1. `packageManager` field in package.json
2. Lockfile detection: `bun.lockb` → `pnpm-lock.yaml` → `yarn.lock` → `package-lock.json`
3. Default: bun (if available) → npm

---

## 🏗️ Project Management

### omg new

Create new projects from templates.

```bash
omg new <stack> <name> [aliases: create]
```

**Available Stacks:**

| Stack | Description |
| ------- | ------------- |
| `rust` | Rust CLI project |
| `react` | React + Vite + TypeScript |
| `node` | Node.js project |
| `python` | Python project |
| `go` | Go project |

**Examples:**

```bash
# Create Rust CLI project
omg new rust my-cli

# Create React project
omg new react my-app

# Create Node.js API
omg new node api-server
```

---

### omg tool

Manage cross-ecosystem CLI tools.

```bash
omg tool <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `install <name>` | Install a tool |
| `list` | List installed tools |
| `remove <name>` | Remove a tool |
| `update <name>` | Update a tool (or `all` to update everything) |
| `search <query>` | Search for tools in the registry |
| `registry` | Show all available tools grouped by category |

**Examples:**

```bash
# Install ripgrep
omg tool install ripgrep

# Install jq
omg tool install jq

# List installed tools
omg tool list

# Remove a tool
omg tool remove ripgrep

# Update all tools
omg tool update all

# Search for docker-related tools
omg tool search docker

# Browse all available tools
omg tool registry
```

**Tool Registry:**

OMG includes a curated registry of 60+ popular developer tools across categories:

- **search**: ripgrep, fd, fzf
- **files**: bat, eza
- **git**: delta, lazygit
- **system**: htop, btop, dust, duf, procs
- **dev**: hyperfine, tokei, just, watchexec
- **node**: yarn, pnpm, tsx, nodemon, prettier, eslint
- **rust**: cargo-watch, cargo-edit, cargo-nextest, bacon
- **python**: black, ruff, mypy, poetry
- **docker**: dive, lazydocker
- **deploy**: vercel, netlify-cli, wrangler

**Tool Resolution:**

1. Check the built-in registry for optimal source
2. Fall back to interactive selection if not in registry
3. Install to isolated `~/.local/share/omg/tools/`

**Secure tool installs:**

OMG treats package installation as execution of untrusted publisher content.
For npm, Cargo, pip, and Go tools it uses an isolated home and configuration,
does not pass ambient registry, Git, SSH, cloud, or CI environment credentials,
uses a fixed system executable path to prevent project-local helper injection,
and keeps the previous working tool until the replacement passes its checks. npm
lifecycle scripts are disabled and registry signatures/provenance are audited;
pip accepts wheels only; Cargo requires the published lockfile; and Go uses the
public module proxy and checksum database.

Registry-backed managers accept registry package names only. npm GitHub
shorthands, Git URLs, tarball URLs, and local package paths are rejected so a
package name cannot silently select a less verified source. Go module paths are
accepted because they are authenticated through the configured module proxy and
checksum database.

The selected manager's resolved executable directory is retained so runtimes
installed by OMG, rustup, or another user runtime manager continue to work.
Other caller `PATH` entries are removed, and a manager executable resolved from
the current project is rejected.

On Linux, secure manager commands run from `/` with absolute destination paths
so Cargo and npm cannot discover configuration by walking from the staging tree
into the user's home. Cargo receives an isolated `CARGO_HOME` and cannot delegate
Git fetching to a host CLI. pip configuration files are disabled explicitly so
global `extra-index-url` settings cannot reintroduce dependency confusion.

Some legitimate tools or private registries need a narrower policy. Exceptions
are comma-separated exact package names and apply only to the current command:

```bash
OMG_TOOL_DANGEROUSLY_ALLOW_ALL_NPM_SCRIPTS="@scope/reviewed-cli" omg tool install reviewed-cli
OMG_TOOL_ALLOW_PIP_SDISTS="reviewed-cli" omg tool install reviewed-cli
OMG_TOOL_ALLOW_CARGO_UNLOCKED="reviewed-cli" omg tool install reviewed-cli
OMG_TOOL_ALLOW_HOST_ENV="npm:@company/private-cli" omg tool install private-cli
OMG_TOOL_ALLOW_UNVERIFIED="npm:@company/private-cli" omg tool install private-cli
OMG_TOOL_ALLOW_GO_CGO="reviewed-cli" omg tool install reviewed-cli
OMG_TOOL_ALLOW_GO_TOOLCHAIN_DOWNLOAD="reviewed-cli" omg tool install reviewed-cli
```

OMG prints a `Security override:` warning for every matching exception before
the package manager starts. Treat an unexpected warning as a reason to stop and
remove the variable from the current shell.

`OMG_TOOL_ALLOW_HOST_ENV` accepts exact `manager:package` entries such as
`npm:@company/private-cli`, `cargo:private-cli`, `pip:private-cli`, or
`go:example.com/company/private-cli`. It restores the full host environment, so
package scripts and build processes may read every credential available to the
current shell. Use it only for a package and registry you control, in a shell
containing the minimum necessary credential. Multiple approvals can be listed
with commas. Avoid persistent shell-profile exports so an approval does not
silently apply to later releases.

Every successful managed installation contains
`.omg-security-receipt.json`. It records the manager and package, public or
host-configured source policy, every active exception, and the effective npm,
pip, Cargo, and Go protections. It also records the SHA-256 digest of every
published executable or script target using relative paths. Security tooling
can inspect this receipt without relying on terminal history.

Before activation, OMG resolves every regular file and symlink in the tool's
`bin` and npm `.bin` directories. An entry whose final target escapes the staged
installation aborts the update, leaving the previous installed version active.
The previous directory is retained until shared command links also succeed. A
link failure rolls the directory back, removes links introduced by the failed
version, and restores the previous version's commands.

On Linux, every managed package-manager process sets the kernel's
`no_new_privs` flag before execution and receives closed standard input. The
flag is inherited by build and lifecycle-script descendants and cannot be
unset, so executing setuid, setgid, or file-capability programs cannot grant
them new privileges. Closed input prevents install hooks from using OMG's
terminal to request sudo or other interactive credentials. These controls do
not restrict ordinary filesystem or network access.

If a corporate TLS proxy or private certificate authority is required, scope
`OMG_TOOL_ALLOW_HOST_ENV` to the affected package and expose only the necessary
proxy and certificate variables in that shell. The package's build process can
read those values.

Private registries that do not publish npm-compatible registry signatures may
also require `OMG_TOOL_ALLOW_UNVERIFIED` with the exact `manager:package` value.
This skips the final authenticity check and should be limited to an internally
verified artifact. It does not imply `OMG_TOOL_ALLOW_HOST_ENV` or enable npm
scripts; set each exception independently when it is actually required.

The npm script exception is scoped to the requested package installation, but
npm versions without a dependency-level allowlist can execute lifecycle scripts
from that package's transitive dependencies too. Its deliberately explicit name
reflects that risk. OMG first installs with scripts disabled and verifies the
dependency tree, then runs `npm rebuild` only when this exception is active.
Review the complete dependency tree before using it.

Go tool builds default to `CGO_ENABLED=0` and `GOTOOLCHAIN=local`. The CGO
exception permits the selected package to invoke the native C toolchain. The
toolchain-download exception permits Go to fetch and execute a toolchain that
is not already installed; Go's checksum database still authenticates official
downloaded toolchains. Apply only the exception named in OMG's failure message.

These defaults follow the upstream security controls documented by
[npm](https://docs.npmjs.com/viewing-package-provenance/),
[pip](https://pip.pypa.io/en/stable/topics/secure-installs/),
[Cargo](https://doc.rust-lang.org/cargo/commands/cargo-install.html), and the
[Go module system](https://go.dev/ref/mod#authenticating). Linux privilege
containment follows the kernel's
[`no_new_privs` contract](https://docs.kernel.org/userspace-api/no_new_privs.html).
npm provenance proves
the published artifact's origin and integrity; it does not prove that the
publisher's code is safe.

Cargo crates can contain `build.rs`, and explicitly approved npm scripts or
Python source distributions execute publisher-controlled build code. The
isolated environment prevents automatic inheritance of shell credentials, but
it is not a filesystem or network sandbox. Review these packages and use a
container or disposable VM when the publisher is not fully trusted.

---

### omg init

Interactive first-run setup wizard.

```bash
omg init [OPTIONS]
```

**Options:**

| Option | Description |
| -------- | ------------- |
| `--defaults` | Use defaults, no prompts |
| `--skip-shell` | Skip shell hook setup |
| `--skip-daemon` | Skip daemon setup |

**Examples:**

```bash
# Interactive setup
omg init

# Non-interactive with defaults
omg init --defaults

# Skip shell configuration
omg init --skip-shell
```

**Setup includes:**

1. Shell detection and hook installation
2. Daemon startup preference
3. Initial environment capture
4. Completion installation

---

### omg self-update

Update OMG to the latest version.

```bash
omg self-update [OPTIONS] [aliases: up]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--force` | Force update even if already on the latest version |
| `--version <VERSION>` | Update or downgrade to a specific version |

**Features:**

- **Paired Binary Updates**: Installs `omg` and `omgd` from the same verified release archive. Both files are staged before replacement; failures restore the previous files. Each replacement is atomic, but the pair is not one atomic filesystem transaction.
- **Progress Tracking**: Real-time progress bar showing download speed and estimated time remaining.
- **Verification**: Automatically verifies the signature of the downloaded binary before installation.

Archives missing either binary are rejected before installation. Restart any running daemon after updating to load the new code; replacing its executable does not restart it. For the systemd user service, run `systemctl --user restart omgd.service`. Otherwise stop and restart the daemon through the mechanism used to launch it, or log out and back in. An update that reports a rollback problem identifies retained recovery files and must not be treated as successful.

**Examples:**

```bash
# Update OMG
omg self-update

# Using alias
omg up
```

---

### omg config

Get or set configuration values.

```bash
omg config [SUBCOMMAND]
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `get <key>` | Get a configuration value |
| `set <key> <value>` | Set a configuration value |
| `list` | List all configuration values |
| `validate` | Validate configuration file syntax and values |
| `reset [-y]` | Reset configuration to defaults |
| `path` | Show configuration file path |

**Examples:**

```bash
# List all configuration
omg config list

# Get a specific value
omg config get data_dir

# Set AUR build concurrency
omg config set aur.build_concurrency 8

# Disable telemetry
omg config set telemetry.enabled false
```

**Configuration keys:**

- `data_dir` — Data directory path (read-only via CLI)
- `socket` — Daemon socket path (read-only via CLI)
- `telemetry.enabled` — Enable/disable telemetry
- `aur.build_concurrency`, `aur.enable_ccache`, `aur.enable_sccache`, `aur.secure_makepkg`, `aur.makeflags` — AUR build tuning

---

## 📸 Environment & Snapshots

### omg snapshot

Create and restore environment snapshots.

```bash
omg snapshot <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `create [-m <msg>]` | Create a new snapshot (optional message via `-m, --message`) |
| `list` | List all snapshots |
| `restore <id> [-y]` | Restore a snapshot (skip prompt with `-y, --yes`) |
| `delete <id>` | Delete a snapshot |

**Examples:**

```bash
# Create snapshot with message
omg snapshot create -m "Before major upgrade"

# List snapshots
omg snapshot list

# Preview restore
omg snapshot restore abc123 --dry-run

# Restore snapshot
omg snapshot restore abc123

# Delete old snapshot
omg snapshot delete abc123
```

Creation and deletion share a persistent `.index.lock` in the snapshots directory.
A competing mutation fails with a retry message. Both commands validate the index
before changing snapshot files. This does not make the snapshot file and index a
crash-atomic pair.

---

### omg diff

Compare two environment lock files.

```bash
omg diff [OPTIONS] <to>
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--from <file>` | `-f` | First file (default: current environment) |

**Examples:**

```bash
# Compare current env to a lock file
omg diff teammate-omg.lock

# Compare two lock files
omg diff --from old.lock new.lock
```

**Output shows:**

- Packages added
- Packages removed
- Version changes
- Runtime differences

---

## 🤝 Team Collaboration

### omg env

Manage environment lockfiles.

```bash
omg env <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `capture` | Capture current state to `omg.lock` |
| `check` | Check for drift against `omg.lock` |
| `share` | Share via GitHub Gist |
| `sync <url>` | Sync from a shared Gist |

**Examples:**

```bash
# Capture current environment
omg env capture

# Check for drift
omg env check

# Share environment (supply GITHUB_TOKEN through your credential manager;
# never store a literal token in shell history or startup files)
omg env share

# Sync from shared environment
omg env sync https://gist.github.com/user/abc123
```

---

### omg team

Team workspace management.

```bash
omg team <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `init <team-id>` | Initialize team workspace |
| `join <url>` | Join existing team |
| `status` | Show team sync status |
| `push` | Push local environment to team |
| `pull` | Pull team environment |
| `members` | List team members |
| `dashboard` | Interactive team TUI |
| `roles list` | List available roles and permissions |
| `golden-path` | Manage setup templates |
| `compliance` | Check compliance status |
| `activity` | View team activity stream |

**Examples:**

```bash
# Initialize team workspace
omg team init mycompany/frontend --name "Frontend Team"

# Join existing team (gist.github.com URL with a Gist ID)
omg team join https://gist.github.com/mycompany/abc123def456

# Check status
omg team status

# Push changes
omg team push

# Pull updates
omg team pull

# List members
omg team members

# Create golden path template
omg team golden-path create frontend-setup --node 20 --packages "eslint prettier"

# Check compliance and export a report file
omg team compliance --export compliance-report.json

# View activity
omg team activity --days 30
```

**Roles:** admin, lead, developer, readonly

---

## 🐳 Container Management

### omg container

Docker/Podman integration.

```bash
omg container <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `status` | Show container runtime status |
| `shell` | Interactive dev shell |
| `run <image>` | Run command in container |
| `build` | Build container image |
| `init` | Generate Dockerfile |
| `list` | List running containers |
| `images` | List images |
| `pull <image>` | Pull image |
| `stop <container>` | Stop container |
| `exec <container>` | Execute in container |

**Examples:**

```bash
# Check container runtime
omg container status

# Interactive dev shell
omg container shell

# Run command in container
omg container run alpine -- echo "hello"

# Build image
omg container build -t myapp

# Generate Dockerfile
omg container init

# List containers
omg container list

# Stop container
omg container stop mycontainer
```

---

## 🔄 CI/CD & Migration

### omg ci

Generate CI/CD configuration for your project.

```bash
omg ci <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `init <provider> [--advanced]` | Generate CI config (github, gitlab, circleci; optional `--advanced` matrix) |
| `validate` | Validate environment matches CI expectations |
| `cache` | Show recommended cache paths |

**Examples:**

```bash
# Generate GitHub Actions workflow
omg ci init github

# Generate GitLab CI config
omg ci init gitlab

# Validate CI environment
omg ci validate

# Get cache paths for CI
omg ci cache
```

**Generated config includes:**

- OMG installation step
- Cache configuration keyed to `omg.lock`
- Environment validation
- Task execution via `omg run`

---

### omg migrate

Cross-distro migration tools.

```bash
omg migrate <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `export` | Export environment to portable manifest |
| `import <file>` | Import from manifest |

**Examples:**

```bash
# Export current environment
omg migrate export -o my-setup.json

# Preview import
omg migrate import my-setup.json --dry-run

# Import and install
omg migrate import my-setup.json
```

**Manifest includes:**

- All installed packages with versions
- Runtime versions
- Configuration settings
- Automatic package name mapping between distros

---

## 🏢 Enterprise Features

### omg fleet

Fleet management for multi-machine environments.

```bash
omg fleet <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `status` | Show fleet health across machines |

**Examples:**

```bash
# View fleet status
omg fleet status
```

**Status shows:**

- Compliance percentage
- Machines by state (compliant, drifted, offline)
- Team breakdown

---

### omg enterprise

Enterprise administration features.

```bash
omg enterprise <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `reports` | Generate executive reports (JSON) |
| `policy show` | Show current policies |
| `audit-export` | Export compliance evidence |
| `license-scan` | Scan for license compliance |

**Examples:**

```bash
# Generate monthly report (reports are written as JSON)
omg enterprise reports --report-type monthly

# Export SOC2 compliance evidence
omg enterprise audit-export --framework soc2 --period 2025-Q4

# Scan for license issues and export CSV results
omg enterprise license-scan --export csv

# Show current policies
omg enterprise policy show
```

**Report types:** monthly, quarterly, custom
**Accepted framework labels:** soc2, iso27001, fedramp, hipaa, pci-dss. This enterprise command generates the same generic Arch inventory bundle for each label, not framework-specific controls. It exports up to 100 recent audit entries. `--period` does not filter them. Files are plaintext, not encrypted or certified compliance evidence. See [enterprise export limits](./enterprise.md).

> Note: policy management beyond `policy show` and self-hosted registry
> management are not available in the CLI.

---

## 📜 History & Rollback

### omg history

View transaction history.

```bash
omg history [OPTIONS]
```

**Options:**

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--limit <N>` | `-l` | Number of entries (default: 20) |
| `--search <pkg>` | `-s` | Search for a specific package in history |
| `--type <type>` | `-t` | Filter by transaction type (install, remove, update, sync) |
| `--from <date>` | | Filter transactions from this date (YYYY-MM-DD) |
| `--to <date>` | | Filter transactions until this date (YYYY-MM-DD) |

**Examples:**

```bash
# View recent history
omg history

# View last 5 transactions
omg history --limit 5

# Search history for a package
omg history --search firefox
```

---

### omg rollback

Rollback to a previous state.

```bash
omg rollback [transaction-id] [-y]
```

**Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--yes` | `-y` | Auto-confirm without prompting (required in non-interactive mode) |

**Examples:**

```bash
# Interactive rollback (most recent transaction)
omg rollback

# Rollback specific transaction
omg rollback abc123
```

---

## 📊 Dashboard

### omg dash

Launch interactive TUI dashboard.

```bash
omg dash [aliases: d]
```

**Keyboard Controls:**

| Key | Action |
| ----- | -------- |
| `q` | Quit |
| `r` | Refresh |
| `/` | Search packages |
| `Tab` | Switch view |

---

### omg stats

Display usage statistics.

```bash
omg stats
```

---

### omg metrics

Show system metrics (Prometheus-style). Unix only.

```bash
omg metrics
```

---

### omg daemon-status

Show detailed daemon status.

```bash
omg daemon-status
```

---

### omg generate-man

Generate man pages for OMG commands.

```bash
omg generate-man [--output <dir>]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--output <dir>` | `-o` | Output directory for man pages (default: ~/.local/share/man/man1) |

---

## 🔑 Dashboard account & daemon

### omg account

Optional link between this machine and the OMG dashboard. Linking attributes opted-in usage; every local command works without it.

`omg license`, `omg license check`, and `omg license pricing` were removed in 0.1.215.

```bash
# Removed
omg license
omg license check
omg license pricing

# Use instead
omg account status
omg account link --token-stdin
omg account unlink
```

```bash
omg account <SUBCOMMAND>
```

**Subcommands:**

| Subcommand | Description |
| ------------ | ------------- |
| `link --token-stdin` | Read the dashboard token from standard input, not argv |
| `status` | Show whether this machine is linked |
| `unlink` | Remove the local dashboard identity |

### omg daemon

Start the background daemon (Unix only). It takes no subcommands — for daemon
status, see [`omg daemon-status`](#omg-daemon-status).

```bash
omg daemon [--foreground]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--foreground` | `-f` | Run in foreground (don't daemonize) |

For direct daemon control:

```bash
omgd  # Run the daemon (it blocks in the foreground; use systemd or `omg daemon` to manage it)
omgd --socket /path/to/socket  # Custom socket path
```

---

## ⚡ Ultra-Fast Queries

Prompt counters and hot-path queries run through the main `omg` binary without starting the full async runtime.

```bash
omg <subcommand>
```

**Prompt counters:**

- `ec`: explicit count
- `tc`: total count
- `uc`: update count
- `oc`: orphan count

These counters have no universal latency guarantee.

**Hot-path commands:**

- `status`: system status
- `search` / `s`: package search
- `install` / `i`: package installation
- `remove` / `r`: package removal
- `update` / `u`: package update
- `sync` / `sy`: database sync
- `info`: package details
- `list` / `ls`: list runtimes
- `dash` / `d`: terminal dashboard
- `self-update` / `up`: update CLI and daemon binaries together

Execution paths and costs depend on the backend and daemon availability.

**Examples:**

```bash
# Get package counts for shell prompt
omg ec
omg tc

# Full status and package queries
omg status
omg search vim
omg info vim
```

---

## 🌍 Global Options

These options work with all commands:

| Option | Short | Description |
| -------- | ------- | ------------- |
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |
| `--verbose` | `-v` | Increase verbosity; repeat (`-vv`) for more detail, also streams package build output live |
| `--quiet` | `-q` | Suppress non-essential output (command results still print) |
| `--json` | | Output in JSON format (for scripting). Implies quiet output: stdout carries pure JSON while diagnostics go to stderr |
| `--all-commands` | | Show all commands including advanced ones |

---

## 📚 See Also

- [Quick Start Guide](./quickstart.md)
- [Configuration](./configuration.md)
- [Runtime Management](./runtimes.md)
- [Security & Compliance](./security.md)

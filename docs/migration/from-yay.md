---
title: Migrating from yay
sidebar_label: From yay
sidebar_position: 1
description: Command mapping and migration guide from yay to OMG
---

# Migrating from yay

**In plain words:** If you used the yay helper before, this page maps the commands you already know to their OMG equivalents and states plainly where the behaviour differs.

> New to the terminal? Read [Getting started](../getting-started.md) and keep
> [the glossary](../glossary.md) open while you work.

This guide helps yay users transition to OMG with familiar command patterns and enhanced capabilities.

## Why Migrate?

| Feature | yay | OMG |
| --------- | ----- | ----- |
| Search behavior | Official repositories and AUR | Official repositories and AUR; use `--no-aur` for official-only results |
| Runtime Management | ❌ | ✅ Node, Python, Go, Rust, Ruby, Java, Bun |
| Security Scanning | ❌ | ✅ CVE scanning, SBOM generation |
| Team Sync | ❌ | ✅ Environment lockfiles |
| Language | Go | Rust, with native-tool subprocesses on some paths |

OMG is approaching beta. Keep yay and pacman available while validating your required workflows. Comparisons above describe command intent, not complete feature equivalence. See [benchmark scope](../../benchmarks/README.md) and [security limits](../security.md).

## Command Mapping

### Package Operations

| yay | OMG | Notes |
| ----- | ----- | ------- |
| `yay -Ss <query>` | `omg search <query>` | Official and AUR results; output is not guaranteed identical |
| `yay -S <pkg>` | `omg install <pkg>` | Security grading included |
| `yay -R <pkg>` | `omg remove <pkg>` | Review the removal plan and OMG's flags |
| `yay -Syu` | `omg update` | Updates official + AUR |
| `yay -Si <pkg>` | `omg info <pkg>` | Richer metadata |
| `yay -Sc` | `omg clean --cache` | Requests package-cache cleanup |
| `yay -Qe` | `omg explicit` | List explicitly installed |
| `yay -Sy` | `omg sync` | Sync databases |

### Interactive Mode

```bash
# yay interactive search
yay <query>

# OMG equivalent (search includes AUR by default; add -d for details)
omg search <query>
```

### AUR Operations

OMG handles AUR transparently:

```bash
# Search includes AUR automatically
omg search spotify

# Install from AUR (auto-detected)
omg install spotify

# Update AUR packages
omg update
```

Run these commands as your regular account. Unlike workflows that start the helper with sudo, OMG keeps fetching, review, and package building unprivileged and requests sudo only for its validated package transaction. `sudo omg ...` is deprecated; AUR builds already refuse to run when OMG starts as root.

OMG reviews and re-hashes the recipe, builds offline in Bubblewrap by default, inspects the resulting archive, and passes sealed bytes to the privileged consumer. Packages containing install hooks, setuid/setgid files, or file capabilities require separate attended approval. These controls follow Arch's documented [PKGBUILD execution and install-script model](https://man.archlinux.org/man/PKGBUILD.5), Bubblewrap's [caller-defined sandbox model](https://github.com/containers/bubblewrap/blob/main/README.md#sandbox-security), and Linux's [`memfd_create(2)` sealing semantics](https://man7.org/linux/man-pages/man2/memfd_create.2.html).

## Configuration Migration

### yay config location

```
~/.config/yay/config.json
```

### OMG config location

```
~/.config/omg/config.toml
```

## New Capabilities

After migrating, you gain access to:

### Runtime Management

```bash
omg use node 20
omg use python 3.12
omg list node --available
```

### Security Scanning

```bash
omg audit
omg audit sbom --output sbom.json
```

### Team Sync

```bash
omg env capture
omg env share
```

## Next Steps

- [CLI Reference](../cli.md) — Full command documentation
- [Configuration](../configuration.md) — All config options
- [Security](../security.md) — Vulnerability scanning setup

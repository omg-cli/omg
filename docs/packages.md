---
title: Package management
sidebar_position: 10
description: Search, install, update, remove, and clean packages on a supported system
---

# Package management

OMG works with the package system for your operating system. This page shows the common commands and explains where behavior depends on the backend. A package is software installed through that system. Start with [getting started](./getting-started.md) if you have not used a terminal before.

## What you need first

- A [supported backend and build](./installation.md). Arch supports official repositories and the Arch User Repository (AUR). Debian and Ubuntu use APT, Fedora uses DNF, and macOS uses Homebrew. Native Windows has no backend.
- Permission to install or remove software. Run `omg` as your regular user; it asks for elevation when a system transaction needs it.

| System | Package source | Important limit |
| --- | --- | --- |
| Arch Linux | Official repositories and AUR | AUR recipes need review and a build. Arch has the broadest package workflow. |
| Debian or Ubuntu | APT | No AUR. Cache cleanup is not implemented in the APT backend. |
| Fedora | DNF and RPM | No AUR. Some audit and rollback features have separate backend limits. |
| Apple Silicon macOS | Homebrew | No AUR. The published macOS release targets ARM64. |
| Windows | None natively | Use a supported Linux distribution inside WSL. |

Published Linux release archives are backend-specific and target x86_64.
See [installation](./installation.md) for build features, system dependencies,
and the release matrix. The `debian-pure` feature is for index and test work;
it refuses live Debian or Ubuntu package mutations.

## Find a package

```bash
omg search ripgrep
```

The default result limit is 15. On Arch, search also queries the AUR unless you pass `--no-aur`. A result is a name and source match, not a safety verdict. An attended terminal offers a picker to open a result's details. It does not install the selected package.

```bash
omg search ripgrep --no-aur --limit 30
omg info ripgrep
omg why ripgrep
omg outdated
```

See [package search](./package-search.md) for ranking, JSON output, and network limits. `omg info` shows the fields available from that source; it does not promise the same metadata on every backend.

## Preview and install

`omg install` changes your package database and may install other packages that the requested package needs. Review the preview before the transaction.

```bash
omg install --dry-run ripgrep
```

```bash
omg install ripgrep
```

You can name multiple packages. With no name, `omg install` opens a package picker in an attended terminal and requires you to select one package. It fails when there is no terminal. `--yes` skips the normal confirmation; it does not choose a package or bypass separate AUR approval. Installing a local archive requires `--allow-local-file` in addition to the archive path.

On Arch, an AUR package goes through the [AUR build and review](./aur.md). An official package follows the selected native backend. OMG applies its configured [security policy](./security.md) before supported install paths, but a grade does not certify that a package is safe.
Use `omg config path` to find your configuration file. See
[configuration](./configuration.md) for AUR settings and policy keys.

## Check and apply updates

`omg update` can change many packages and runtimes. Check what is available first.

```bash
omg update --check
```

```bash
omg update --dry-run
```

```bash
omg update
```

The normal Arch path handles official packages and installed AUR packages. `--aur-only` updates AUR packages without an official database sync or system upgrade. It conflicts with `--fast` and `--turbo`. `--no-sync` uses cached package metadata, `--fast` combines sync and upgrade without a preview, and `--turbo` skips sync and uses cached data. Read the [CLI reference](./cli.md#omg-update) and any backend warning before using these modes.

## Remove a package

Removal changes the installed package set. Preview it first.

```bash
omg remove --dry-run ripgrep
```

```bash
omg remove ripgrep
```

`omg remove --recursive ripgrep` also removes unused dependencies on the Arch backend. Other backends do not promise that behavior. The native package system decides whether a dependency conflict blocks removal.

## Inspect counts and clean up

```bash
omg status
omg explicit
omg explicit --count
omg clean
```

Bare `omg clean` shows available cleanup actions. Cleanup can remove package archives needed for rollback, so preview the chosen action first.

```bash
omg clean --cache --dry-run
omg clean --orphans --dry-run
```

On Arch, `--cache` keeps one recent package version by default and warns when recent history refers to versions that cleanup may remove. The warning does not preserve those versions. `--aur` removes AUR build directories and `--all` combines orphan, cache, and AUR cleanup. The APT backend supports orphan cleanup but rejects `--cache`, `--aur`, and `--all`. Fedora supports orphan and downloaded package cache cleanup, but has no AUR cleanup. See [caching](./cache.md) and [history](./history.md) before deleting artifacts.

`omg sync` refreshes package database metadata. It does not install updates.

## History and recovery

```bash
omg history --limit 5
```

OMG records supported transactions, but the log is not a record of every native package manager action. `omg rollback` can reverse some recorded changes if the backend and exact older packages are available. It is not a machine backup. Read [history and rollback](./history.md) before using it.

## If something goes wrong

| What you see | What to do |
| --- | --- |
| No search results | Check spelling and source configuration. Refresh metadata with `omg sync`, then try the native package tool. |
| An AUR build fails | Keep the error output. Check [AUR troubleshooting](./aur.md#if-something-goes-wrong) before changing build settings. |
| A permission or daemon error | Run `omg doctor` and read [troubleshooting](./troubleshooting.md). Do not run the AUR build as root. |
| A cleanup option is rejected | Check this page's backend limits and `omg clean --help`. |

## Where to go next

- [CLI reference](./cli.md) lists every package option.
- [AUR support](./aur.md) explains community builds and approvals.
- [History and rollback](./history.md) explains what recovery requires.
- [Troubleshooting](./troubleshooting.md) shows how to report a failed command.

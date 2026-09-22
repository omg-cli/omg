---
title: AUR support
sidebar_position: 11
description: Search, review, build, and update Arch User Repository packages
---

# AUR support

The Arch User Repository (AUR) contains build recipes submitted by Arch users. OMG can find and install these packages on an Arch backend. A recipe can run code during a build, so review it before you install it. See the [glossary](./glossary.md) if the terms here are new.

## What you need first

- An [Arch backend build](./installation.md). Other backends have no AUR build path.
- A regular user account and the tools needed to build the selected recipe. Run `omg` without `sudo`; an AUR build started as root is refused.
- An attended terminal for the default PKGBUILD review. The default build method also needs Bubblewrap.

## Search and install

```bash
omg search visual-studio-code
omg info visual-studio-code-bin
omg install --dry-run visual-studio-code-bin
```

`omg search` combines official repository and AUR matches on Arch. Pass `--no-aur` for an official-only search. Search results and AUR votes are source metadata, not a safety judgment. The remote AUR query has a four-second timeout; an unavailable AUR source can leave only official results.

Installing changes your system. After reviewing the preview and recipe, run:

```bash
omg install visual-studio-code-bin
```

OMG asks before the package transaction. `--yes` skips that normal confirmation but does not answer the separate attended approval for an archive with an install hook, setuid/setgid files, or file capabilities.

## What OMG checks

1. OMG fetches recipe sources without executing the PKGBUILD, then presents the source tree for review when `aur.review_pkgbuild` is enabled.
2. It hashes and rechecks the reviewed tree before the build. The default Bubblewrap path isolates the build home and environment and denies build network access unless configured otherwise.
3. It inspects output archives before installation. The inspector rejects unsafe paths, escaping links, special entries, and inconsistent or undeclared metadata.
4. Outputs with privileged integration, such as install hooks, capabilities, systemd units, kernel modules, package-manager hooks, or `/etc` content, receive a second private build. The outputs must match byte for byte.
5. Accepted archive bytes move through a sealed in-memory handoff to the privileged transaction, which reinspects the staged bytes.

These checks reduce specific build and handoff risks. A reproducible malicious recipe remains malicious. A package hash is not a publisher signature. Check the recipe's source verification, including `validpgpkeys`, and the upstream project before trusting it. Read [security](./security.md) for the limits of grades and audit evidence.

## Review and unattended runs

PKGBUILD review defaults to on. With review enabled, a session without an interactive terminal fails before building. `omg install --review PACKAGE` or `omg update --review` forces review even when configuration has disabled it. Turning review off does not disable archive inspection or the separate exceptional privilege approval.

Do not assume `--yes` makes every AUR package suitable for CI. An archive that requires attended approval fails without a terminal. Use reviewed, pinned artifacts and test the exact recipe in your CI environment.

## Configure builds

The defaults below come from `src/config/settings.rs`. Edit your OMG configuration file, whose location `omg config path` prints.

```toml
[aur]
build_method = "bubblewrap"
build_concurrency = 1
review_pkgbuild = true
allow_network = false
allow_unsafe_builds = false
```

`build_method` also accepts `chroot` and `native`. Native builds require the explicit `allow_unsafe_builds` opt-in. Chroot devtools can execute recipe code on the host before isolation and need the unsafe opt-in; they cannot enforce an offline build. Keep the default unless you understand those limits. `makeflags`, `cache_builds`, `enable_ccache`, `enable_sccache`, `pkgdest`, and `srcdest` are optional settings. A higher `build_concurrency` uses more CPU and memory and is not a guarantee of a faster build.

## Update or remove

```bash
omg update --check
omg update --aur-only
omg remove visual-studio-code-bin
```

`--aur-only` checks and updates installed AUR packages without the official system upgrade. The regular `omg update` path also handles official updates. Removal follows the installed package database, subject to its dependency checks.

## If something goes wrong

| What you see | What to do |
| --- | --- |
| Review needs a terminal | Run the command in an attended terminal. Changing `review_pkgbuild` accepts the risk of unreviewed recipe code. |
| Bubblewrap is missing | Install Bubblewrap through your system package manager, then retry. |
| Source fetch or build fails | Keep the full error output. Check network access for source fetching, recipe checksums, and required build tools. |
| Sudo asks again after a long build | Complete the prompt as your regular user. The background refresh is conditional and cannot promise that credentials never expire. |
| A package asks for exceptional privilege approval | Inspect the archive warning. `--yes` cannot approve it. |

## Where to go next

- [Package management](./packages.md) covers the other package commands.
- [Configuration](./configuration.md) lists settings and paths.
- [History and rollback](./history.md) explains recovery limits.
- [Troubleshooting](./troubleshooting.md) explains what to include in a report.

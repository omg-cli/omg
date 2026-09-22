---
title: Cheat Sheet
sidebar_position: 99
description: Everyday OMG commands grouped by what you want to do, with one-line explanations and their limits
---

# OMG cheat sheet

**In plain words:** One page of the commands people use most, grouped by what you want to do rather than by command name. Keep it open in a second window while you work.

This page is a short list of commands to keep nearby. Each group starts with something you might want to do, then shows the commands and explains each one in a line. Print it if you like.

**New to the terminal?** Read [Getting started](./getting-started.md) first, and use [the glossary](./glossary.md) for words you do not know.

Two things to know before you use this page:

- Install OMG first, using the reviewed-download procedure in [Installation](./installation.md). Every example below assumes OMG is installed.
- Choose version numbers that match your project. The versions in these examples are examples only, not a current security recommendation.

## I want to check that OMG is healthy

```bash
omg --version
omg doctor
omg status
omg daemon-status
```

- `omg --version` prints the installed version.
- `omg doctor` checks the machine's setup and reports problems (it exits 0 when healthy, 1 when it finds issues).
- `omg status` shows a short system summary.
- `omg daemon-status` shows whether the background helper is running on Unix builds.

For the exact options of any command, add `--help`. For example:

```bash
omg search --help
omg --all-commands --help
```

A global `--json` option exists, but it does not guarantee that every command implements a stable JSON response.

## I want to find and understand a package

```bash
omg search ripgrep
omg info ripgrep
omg why ripgrep
omg explicit --count
omg outdated
```

- `omg search` finds packages. On Arch it includes the AUR unless you add `--no-aur`.
  In an attended terminal, you can select a result to open details without installing it.
- `omg info` shows one package's details.
- `omg why` explains why a package is installed, through the chain of packages that need it.
- `omg explicit --count` prints how many packages you asked for yourself.
- `omg outdated` lists the packages that have newer versions available.

## I want to change packages

> **Warning:** these commands change your computer except when they include the preview options shown here. Read each preview before you drop `--dry-run` or `--check`.

```bash
omg install --dry-run ripgrep
omg remove --dry-run ripgrep
omg update --check
omg update --dry-run
omg clean --dry-run --all
```

- A preview (`--dry-run` or `--check`) prints what would happen and changes nothing.
- After you review the preview, run the same command without the preview option to request the change.
- `omg sync` refreshes your computer's list of what the repositories currently offer.
- With no package name, `omg install` opens an interactive picker instead of installing a package you named.
- Backends differ, so options that work only on Arch are not portable transaction controls. Cleanup can remove rollback artifacts. See [Package management](./packages.md).

## I want to choose a language version for my project

```bash
omg list node
omg list node --available
omg which node
omg use node 22
```

- `omg list` shows installed versions. With a runtime name, `--available` lists
  remote versions instead; it does not add them to the installed list.
- `omg which` prints the version that is active now.
- `omg use` switches to a version and installs it first if it is missing.

> **Warning:** `omg use` can download and install software, and `omg run` (below) runs code from the project folder. Review a repository you do not trust before using either.

Supported native runtime names are `node`, `python`, `go`, `rust`, `ruby`, `java`, `bun`, `deno`, `pi`, `zig`, `dotnet`, `erlang`, `php`, and `swift`.

For Rust, `rust-toolchain.toml` must contain TOML, not a bare channel name:

```toml
[toolchain]
channel = "stable"
```

## I want to run my project's tasks

```bash
omg run build
omg run test -- --verbose
```

`omg run` runs a task the project already defines. It always needs a task name, and it does not invent a task that the project does not define. Everything after `--` is passed to the project's own tool.

Follow [shell integration](./shell-integration.md) for your shell's hook and for tab-completion. Directory-change activation selects versions you already installed; it is not a dependency installer.

## I want to record and share my environment

```bash
omg env capture
omg env check
omg env share
omg env sync https://gist.github.com/USER/GIST_ID
```

- `omg env capture` writes a record of the environment into `omg.lock` in the current folder.
- `omg env check` compares that record with the machine and reports drift; it does not fix drift.
- `omg env share` uploads the record and needs credentials (a GitHub token in `GITHUB_TOKEN`).
- `omg env sync` downloads a shared record and checks drift without installing packages.
- Environment records need the Arch or Debian package system.
- Review private inventory before sharing. An unlisted Gist is not encrypted. See [Team workflows](./team.md).

## I want to check security evidence

```bash
omg audit policy
omg audit scan
omg audit verify
omg audit sbom -o sbom.json
```

These operations have [backend and evidence limits](./security.md). Scan findings alone do not cause failure. System SBOM generation supports Arch, Debian, Ubuntu, and Fedora builds; exports are plaintext. Local log verification proves neither authenticity nor completeness. The SLSA-named command does not verify a SLSA build level.

## I want to undo a change

```bash
omg history
omg rollback TRANSACTION_ID
```

Inspect history before you consider `omg rollback`: rollback changes packages and is not a complete machine restore. Never reset malformed history or audit logs. See [history](./history.md) and [troubleshooting](./troubleshooting.md).

## I want to change settings or use optional tools

```bash
omg config path
omg config list
omg config validate
omg account status
omg container status
omg hooks status
omg hooks uninstall
omg dash
```

- `omg config` reads and checks OMG's settings; `config path` prints where the settings file lives.
- `omg account status` shows whether this machine is linked to an optional dashboard account
  in builds with the `license` feature.
- `omg container status` shows whether Docker or Podman is available.
- `omg hooks status` and `omg hooks uninstall` manage the Git hooks OMG can install in a project.
- `omg dash` opens a full-screen dashboard: `Tab` selects views, `r` requests a refresh, and `q` quits outside text entry.

Configuration output may disclose private settings; review it before sharing. Account linking accepts a token through standard input (`omg account link --token-stdin`), never on the command line. Use a credential manager rather than putting tokens in shell start-up files.

`omg hooks uninstall` removes only byte-exact current OMG hook templates. Custom, composed, historical, and nonregular files stay in place.

## I want to use OMG in CI

CI needs a pinned, verified installer or artifact and a prepared, backend-compatible environment; a moving `curl | bash` URL is not a release pin.

## Where to go next

- [CLI reference](./cli.md) for every command and option.
- [Configuration](./configuration.md) for settings keys.
- [Containers](./containers.md) for the container commands.
- [Security](./security.md) and [history](./history.md) for the limits behind the audit and rollback commands.
- [Troubleshooting](./troubleshooting.md) when a command fails.

If a command on this page does not behave as described, [open an issue](https://github.com/omg-cli/omg/issues) with your OMG version, your Linux distribution or macOS version, the command, and the output. Remove passwords, tokens, and private folder names first.

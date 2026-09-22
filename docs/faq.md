---
title: FAQ
sidebar_position: 51
description: Frequently asked questions
---

# Frequently asked questions

**In plain words:** Short answers to the questions people ask most, including the things OMG deliberately does not do.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

## What is OMG?

OMG is one program that you use in a terminal window. It installs, updates, and removes
software, picks the right version of a programming language for a project, and runs the
tasks a project already defines.

It covers system packages, 14 language runtimes, a task runner, and some security checks.
It is **approaching beta**, so its makers still change how it behaves, and it does not
replace every feature of `pacman`, APT, DNF, Homebrew, or the runtime tools you may
already use.

## How do I install it?

Follow [installation](./installation.md). In short: download the installer, read it, then
run it. It checks the download before installing anything.

- The check needs the GitHub CLI program, `gh`. If `gh` is missing, installation stops.
- Releases exist for Arch, Debian, Ubuntu, and Fedora on 64-bit Intel or AMD, and for
  Apple Silicon Macs.
- Native Windows is not supported. Inside WSL (a real Linux system inside Windows), use
  the file for the Linux distribution you installed.
- Building from source is also possible; it needs Rust and the right backend flags.

## How do I find a command or option?

Run `omg --help` for the main commands, or `omg --all-commands --help` to include
advanced commands. Run `omg <command> --help` for that command's arguments and
options. The [CLI reference](./cli.md) explains behavior and platform limits;
the help output shows what your installed build accepts.

## Is it faster?

Sometimes, for repeated searches and read-only lookups, OMG can answer from a warm cache
or read your package database directly. Downloads, installations, and network requests
take the time they take.

Measure it on your own machine, with the same query and the same cache state, and treat
the [benchmark records](../benchmarks/README.md) as measurements of their recorded
conditions. No universal speedup is promised.

## Does it replace my normal package manager?

No. OMG uses each system's package database and transaction path. Arch uses ALPM,
Debian and Ubuntu use APT, Fedora uses RPM and DNF, and macOS uses Homebrew. Keep
the native tool available, especially for repairs.

AUR support does not promise every `yay` or `paru` option, and AUR recipes are community
code that runs on your machine. See [package management](./packages.md) and
[AUR](./aur.md).

## Does it collect telemetry?

Not unless you turn it on. Installer telemetry asks your permission and defaults to no;
runtime telemetry is opt-in. `OMG_NO_TELEMETRY=1` turns off installer telemetry, and
`OMG_TELEMETRY=0` turns off runtime telemetry.

Commands still contact package repositories, runtime providers, advisory services, and any
account service you enabled, because that contact is how they work. See
[privacy and telemetry](./security.md#privacy-and-telemetry).

## Which runtimes can it manage?

Fourteen: Node.js, Python, Go, Rust, Ruby, Java, Bun, Pi, Deno, Zig, .NET, Erlang, PHP,
and Swift.

A name that OMG does not manage fails with a message instead of guessing. Each runtime has
its own platform requirements, so read them before you replace the tooling you already
have. See [runtime management](./runtimes.md).

## Why use a shell hook?

The hook runs when you enter a project folder and puts its installed runtime version
at the front of your `PATH`. `omg init` can add the hook to your shell's start-up
file, or you can add the line shown in [shell integration](./shell-integration.md).

Technically, the generated hook saves the original `PATH`, restores it when you leave the
folder, and calls `command omg hook-env` on each prompt so that a shell function named
`omg` cannot shadow the real binary. Zsh caches the prompt counters for 60 seconds; Bash
re-reads the snapshot file on each prompt; Fish registers on `PWD` and `fish_prompt` and
does not define the counter helpers at all.

It switches between versions you already installed; it does not install a missing version
by itself. Use the hook from only one runtime manager to avoid conflicts. See
[shell integration](./shell-integration.md).

## Does `omg.lock` reproduce an environment?

No. It records what was there. The file lists runtime versions, the packages you installed
yourself, and a SHA-256 fingerprint over the normalized lists, plus a schema version and a
timestamp.

`omg env check` recomputes that fingerprint and reports the differences between the record
and this machine. `omg env sync` downloads someone else's record and reports differences
there too; it backs up a differing local file rather than overwriting it silently. Neither
installs software, and neither rebuilds a machine.

Capture requires a build with the Arch or Debian backend — a Fedora build refuses instead
of writing a partial record, so a passing check on an unsupported backend is not possible.

Review a lockfile before you share it: it can reveal what is on your computer. A secret
GitHub Gist is unlisted, not encrypted.

## What do the security commands prove?

Less than their names might suggest, and that is deliberate.

- The SLSA-named check verifies an artifact's signature. The current verifier
  requires `--certificate-identity` and rejects a missing or empty value.
  A valid signature does not establish a SLSA build level.
- Local audit chains show that the record has not changed since it was written. They do not
  prove who wrote it or that nothing is missing.
- SBOM and compliance exports are plain text files, to be read by a person or a tool.
- HIPAA export is not implemented.

Read [security](./security.md) and
[the retained-trust boundaries](../SECURITY.md#security-boundaries-and-retained-trust).

## Can I undo an installation?

Sometimes. OMG records transactions where your system's package tool supports it, and
`omg rollback` can return to an earlier recorded state.

It is not a disk snapshot. Whether it works depends on your system, the older package
versions still being available, and your current dependencies. Read `omg history` and
[history and rollback](./history.md) before you change anything.

Never reset or edit a damaged history or audit log to make an error message disappear;
that destroys the evidence.

## What does `omg dash` do?

It opens a dashboard inside your terminal window. `Tab` changes view, `r` asks for a
refresh, and `q` quits while you are not typing in a text box.

Some views stay empty when your system's package tool or an optional service is not
available. An empty view is not proof that there is nothing to find. See
[terminal dashboard](./tui.md).

## How do I diagnose daemon problems?

Run `omg daemon-status` first, then follow [troubleshooting](./troubleshooting.md). Only
run a daemon if the release you installed contains one.

Do not delete sockets, caches, or records to make an error message go away: that hides the
cause and can destroy data.

## Where can I get help, or contribute?

- Report a bug in [GitHub Issues](https://github.com/omg-cli/omg/issues) with your OMG
  version (`omg --version`), your Linux distribution or macOS version, the command, and the
  output. Remove passwords, tokens, and private folder names first.
- Report a security problem privately, as described in [SECURITY.md](../SECURITY.md).
- Contribution steps, code standards, and test environments are in
  [CONTRIBUTING.md](../CONTRIBUTING.md).
- OMG is open source under the [MIT License](../LICENSE).

## Where to go next

- [Getting started](./getting-started.md) if you have never used a terminal window.
- [Glossary](./glossary.md) for plain-language definitions of the words used here.
- [Installation](./installation.md) and [Quickstart](./quickstart.md) to get going.
- [Troubleshooting](./troubleshooting.md) when a command fails.

---
title: FAQ
sidebar_position: 51
description: Frequently asked questions
---

# Frequently asked questions

## What is OMG?

OMG combines system-package commands, 14 native runtime managers, a task runner, and selected security tools. It complements pacman, APT, DNF, Homebrew, and existing runtime providers rather than hiding the systems underneath.

## How do I install it?

Follow [installation](./installation.md): download and inspect the installer before execution and satisfy its archive-attestation prerequisites. Source builds require the correct backend feature flags. Linux releases are backend-specific x86_64 archives; macOS releases target ARM64. Native Windows is unsupported. WSL uses its installed Linux distribution, not a separate Windows backend. See installation for recorded Fedora release failures and daemon availability.

## Is it faster?

Some repeated queries benefit from cached indexes and direct reads. Native subprocesses, network access, and package transactions have different costs. Use the [benchmark records](../benchmarks/README.md) with their host, artifact, sources, and cache conditions; no universal speedup or shell-hook latency is guaranteed.

## Does it replace my native package manager?

No. Backends use native package infrastructure and have different feature and security coverage. Keep native recovery tools. AUR support does not promise every yay or paru option, and AUR recipes execute community code. See [packages](./packages.md) and [AUR configuration](./aur.md).

## Does it collect telemetry?

Installer telemetry requires consent and defaults to no; runtime telemetry is opt-in. `OMG_NO_TELEMETRY=1` disables installer telemetry and `OMG_TELEMETRY=0` disables runtime telemetry. Functional requests to repositories, runtime providers, advisory services, and optional account services remain possible. See [privacy and telemetry](./security.md#privacy-and-telemetry).

## Which runtimes does it manage?

OMG has native managers for 14 runtimes: Node.js, Python, Go, Rust, Ruby, Java, Bun, Pi, Deno, Zig, .NET, Erlang, PHP, and Swift. Unsupported names fail explicitly. Installation and project builds have provider- and platform-specific prerequisites; check them before replacing existing tooling. See [runtime management](./runtimes.md).

## Why use a shell hook?

It activates installed versions selected by project files when changing directories. It does not promise to install missing versions automatically. Avoid conflicting version-manager hooks and follow the instructions for Bash, Zsh, or Fish in [shell integration](./shell-integration.md).

## Does `omg.lock` reproduce an environment?

It records runtime versions, explicit packages, and an environment fingerprint. `omg env check` checks drift; `omg env sync` downloads a lockfile and checks it without installing software. Neither restores a complete machine or makes arbitrary dependency resolution reproducible. Review a lockfile before sharing it: it can disclose private inventory. Secret GitHub Gists are unlisted, not encrypted.

## What do security commands establish?

Coverage depends on the backend and operation. The SLSA-named command verifies supported artifact signatures with an expected identity; it does not establish a SLSA build level. Local audit chains check consistency, not authenticity or completeness. SBOM and compliance exports are plaintext, and HIPAA export is unimplemented. Read [security](./security.md) and [retained trust boundaries](../SECURITY.md#security-boundaries-and-retained-trust).

## Can I undo an installation?

History recording and rollback depend on backend, configuration, available old packages, and current dependencies. They are not complete machine snapshots. Inspect `omg history` and [rollback limitations](./history.md) before changing state. Never reset malformed history or audit records to hide a failure.

## What does `omg dash` do?

It opens a terminal dashboard. `Tab` selects views, `r` requests refresh, and `q` quits outside text entry. Availability of data depends on the backend and configured services; displayed examples are not live proof of coverage. See [TUI](./tui.md).

## How do I diagnose daemon problems?

Use `omg daemon-status` and [troubleshooting](./troubleshooting.md). Only run a daemon supported by your release. Do not blindly delete sockets, caches, or user records to make an error disappear.

## Where can I contribute?

OMG is [MIT licensed](../LICENSE). Follow [contributing](../CONTRIBUTING.md) and report security issues privately through [SECURITY.md](../SECURITY.md).

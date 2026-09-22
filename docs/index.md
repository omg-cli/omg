---
title: OMG documentation
sidebar_position: 1
description: Manage system packages, project runtimes, and environment records
---

# OMG documentation

OMG manages system packages, developer tools, runtime versions, and project tasks from a
terminal. Current releases target Arch Linux, Debian, Ubuntu, Fedora, and Apple silicon
macOS. Some commands depend on the package backend, so check a feature's page before
using it on a new system.

**New to the terminal?** Start with [Getting started](./getting-started.md). It explains the words and shows what you should see after each step. Look up anything unfamiliar in [the glossary](./glossary.md).

**OMG is in beta.** That means its makers still change how it behaves. Keep your native package tools available, and use a machine you can reinstall while you try out package changes.

## Start here

1. [Getting started](./getting-started.md) — a first walkthrough that assumes nothing.
2. [Installation](./installation.md) — pick the right download and install OMG.
3. [Quickstart](./quickstart.md) — choose a runtime and run a task in a project you already have. It does not change system packages.
4. [Cheat sheet](./cheatsheet.md) — the everyday commands on one page.
5. [FAQ](./faq.md) — short, plain answers to common questions.

## Find the right guide

| You want to... | Read |
| --- | --- |
| Search for, install, update, or remove a system package | [Packages](./packages.md) and [package search](./package-search.md) |
| Use community build recipes on Arch | [AUR](./aur.md) |
| Choose a runtime or install a developer tool | [Runtimes](./runtimes.md), [mise compatibility](./mise-compatibility.md), and [CLI reference](./cli.md) |
| Run a task already defined by a project | [Task runner](./task-runner.md) |
| Switch versions when you enter a folder | [Shell integration](./shell-integration.md) |
| Capture, compare, or share an environment | [Workflows](./workflows.md), [portable environments](./environment-portability.md), and [team setup](./team.md) |
| Check vulnerabilities, export an SBOM, or inspect audit records | [Security](./security.md) and [enterprise report limits](./enterprise.md) |
| Use a container or the terminal dashboard | [Containers](./containers.md) and [dashboard](./tui.md) |
| Investigate a failure or an earlier package change | [Troubleshooting](./troubleshooting.md), [history](./history.md), and [cache](./cache.md) |
| Look up every command or setting | [CLI reference](./cli.md) and [configuration](./configuration.md) |

## How OMG works

[Under the hood](./under-the-hood.md) explains the package backends, optional daemon,
runtime selection, AUR checks, and local audit records. For implementation details,
read [architecture](./architecture.md), [daemon](./daemon.md), [IPC](./ipc.md), and
[cache](./cache.md).

## Look up a command or setting

- [CLI reference](./cli.md).
- [Cheat sheet](./cheatsheet.md).
- [Glossary](./glossary.md) — what every technical word in these docs means.
- [Configuration](./configuration.md).
- [FAQ](./faq.md).
- [Migration from yay](./migration/from-yay.md).
- [Update notices](./update-notices.md) and [organization migration](./organization-migration.md).

## Understand the boundaries

Release targets are Linux x86_64 for Arch, Debian, Ubuntu, and Fedora, plus macOS ARM64. Windows use is through WSL, not a native Windows backend. An available backend does not imply equal command coverage. See [installation](./installation.md) for artifact-specific limitations.

Environment capture records inventory. Sync shares a lockfile and checks drift; it does not reconstruct identical machines. Security exports are plaintext evidence inputs, not compliance certifications. SLSA-named artifact checks do not establish SLSA build levels. These distinctions are documented in [security](./security.md) and [team workflows](./team.md).

Performance depends on the operation, backend, query, and cache state. Read [benchmark methodology and raw evidence](../benchmarks/README.md) rather than treating local measurements as universal speedups.

## Operate and contribute

- [Architecture](./architecture.md), [daemon](./daemon.md), [IPC](./ipc.md), and [cache](./cache.md).
- [Performance investigation](./performance-tips.md).
- [Release operations](./release-operations.md) and [release readiness](./release-readiness.md).
- [Local QEMU checks](./qemu-local.md), [macOS QEMU notes](./qemu-macos.md), and [QA loop](./qa-loop.md).
- [Contributing](../CONTRIBUTING.md) and [changelog](./changelog.md).
- [Documentation style](./documentation-style.md) if you write or edit a page.

Historical changelogs, dated investigations, and audit reports describe their recorded state, not current feature guarantees.

[Report a bug](https://github.com/omg-cli/omg/issues) with your version, distribution, command, and redacted output. Report vulnerabilities privately using [SECURITY.md](../SECURITY.md).

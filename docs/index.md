---
title: OMG documentation
sidebar_position: 1
description: Manage system packages, project runtimes, and environment records
---

# OMG documentation

OMG is one program that installs and updates software for you, chooses language versions for a project, and runs the tasks a project defines. It is a Rust command-line tool that works on Arch Linux, Debian, Ubuntu, Fedora, and Apple Silicon macOS.

**New to the terminal?** Start with [Getting started](./getting-started.md). It explains the words and shows what you should see after each step. Look up anything unfamiliar in [the glossary](./glossary.md).

**OMG is approaching beta.** That means its makers still change how it behaves. Keep your native package tools available, and use a machine you can reinstall while you try out package changes.

## Start here

1. [Getting started](./getting-started.md) — a first walkthrough that assumes nothing.
2. [Installation](./installation.md) — pick the right download and install OMG.
3. [Quickstart](./quickstart.md) — choose a runtime and run a task in a project you already have. It does not change system packages.
4. [Cheat sheet](./cheatsheet.md) — the everyday commands on one page.
5. [FAQ](./faq.md) — short, plain answers to common questions.

## Choose a workflow

- [Packages](./packages.md), [package search](./package-search.md), and [AUR](./aur.md).
- [Runtimes](./runtimes.md), [shell integration](./shell-integration.md), and [mise compatibility](./mise-compatibility.md).
- [Task runner](./task-runner.md) and [containers](./containers.md).
- [Environment and team records](./team.md), [workflows](./workflows.md), and [integrations](./integrations.md).
- [Security evidence](./security.md) and [enterprise report limitations](./enterprise.md).
- [Terminal dashboard](./tui.md), [history](./history.md), and [troubleshooting](./troubleshooting.md).

## Go deeper

Two tracks, depending on what you need:

- **Reading and doing:** [Getting started](./getting-started.md), [quickstart](./quickstart.md), [cheat sheet](./cheatsheet.md), and the [glossary](./glossary.md) cover the everyday surface in plain language.
- **Reasoning about behaviour:** [Under the hood](./under-the-hood.md) explains the two-process split, cache freshness, backend query paths, the AUR gates, lockfile contents, and the audit chain — the detail you want when a result is not what you expected. [Architecture](./architecture.md), [daemon](./daemon.md), [IPC](./ipc.md), and [cache](./cache.md) go one level further.

## Look up a command or setting

- [CLI reference](./cli.md).
- [Cheatsheet](./cheatsheet.md).
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

---
title: OMG documentation
sidebar_position: 1
description: Manage system packages, project runtimes, and environment records
---

# OMG documentation

OMG combines system package backends, project runtime selection, and task execution in one Rust CLI. It is approaching beta. Keep your native package tools available and use recoverable machines for package mutations while validating your workflows.

**[Install OMG](./installation.md), then [run a project task](./quickstart.md).** The quickstart selects a runtime without changing system packages.

## Choose a workflow

- [Packages](./packages.md), [package search](./package-search.md), and [AUR](./aur.md).
- [Runtimes](./runtimes.md) and [shell integration](./shell-integration.md).
- [Task runner](./task-runner.md) and [containers](./containers.md).
- [Environment and team records](./team.md), [workflows](./workflows.md), and [integrations](./integrations.md).
- [Security evidence](./security.md) and [enterprise report limitations](./enterprise.md).
- [Terminal dashboard](./tui.md), [history](./history.md), and [troubleshooting](./troubleshooting.md).

## Look up a command or setting

- [CLI reference](./cli.md).
- [Cheatsheet](./cheatsheet.md).
- [Configuration](./configuration.md).
- [FAQ](./faq.md).
- [Migration from yay](./migration/from-yay.md).

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

Historical changelogs, dated investigations, and audit reports describe their recorded state, not current feature guarantees.

[Report a bug](https://github.com/omg-cli/omg/issues) with your version, distribution, command, and redacted output. Report vulnerabilities privately using [SECURITY.md](../SECURITY.md).

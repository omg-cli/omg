---
title: OMG documentation
sidebar_position: 1
description: Learn how OMG manages packages, runtimes, project tasks, and environment records
---

# Learn OMG

OMG gives your development environment one workflow: choose the tools a project needs, run the work it defines, and keep a record of the setup that worked.

**New here? Start with the [quickstart](./quickstart.md).** It takes you from installation to a running project in a few commands.

## Choose your first workflow

### Build and run a project

- [Quickstart](./quickstart.md) — select a runtime, run a task, and capture the environment.
- [Task runner](./task-runner.md) — run scripts from package.json, Cargo, Make, and other supported project types.
- [Runtime management](./runtimes.md) — install and switch Node.js, Python, Rust, Go, and more.
- [Shell integration](./shell-integration.md) — select project versions as you move between directories.

### Manage packages and tools

- [Package operations](./packages.md) — search, inspect, preview, install, and update system packages.
- [Package search](./package-search.md) — understand sources, filters, and result output.
- [Developer tools](./cli.md#omg-tool) — install supported npm, Python, Cargo, Go, and other registry tools.
- [AUR workflow](./aur.md) — review and control source builds on Arch.

### Keep environments understandable

- [Team workflows](./team.md) — capture, compare, and share environment records.
- [Workflow patterns](./workflows.md) — combine runtimes, packages, and tasks in a repeatable project flow.
- [Mise compatibility](./mise-compatibility.md) — see which existing project configuration OMG can reuse.
- [Security model](./security.md) — understand what OMG verifies and where its boundaries are.

## Look up a command or fix a problem

- [CLI reference](./cli.md) — commands, options, and machine-readable output.
- [Cheatsheet](./cheatsheet.md) — common commands at a glance.
- [Installation](./installation.md) — platform requirements, verification, updates, and source builds.
- [Configuration](./configuration.md) — persistent settings and environment variables.
- [FAQ](./faq.md) — common questions and migration notes.
- [Troubleshooting](./troubleshooting.md) — diagnose failed commands and setup issues.

## The operating model

OMG keeps native package backends and project metadata in view while giving you one command surface. Supported targets currently include Linux x86_64 on Arch, Debian, Ubuntu, and Fedora, plus macOS ARM64. Windows use is through WSL2.

Feature coverage varies by backend and project type. Environment records describe the tools and state OMG can observe; they do not recreate an identical machine. The linked workflow and security guides explain those boundaries where they affect a decision.

## For maintainers and contributors

- [Architecture](./architecture.md), [daemon](./daemon.md), [IPC](./ipc.md), and [cache](./cache.md).
- [Release operations](./release-operations.md), [release readiness](./release-readiness.md), and [QA loop](./qa-loop.md).
- [Contributing](../CONTRIBUTING.md) and [changelog](./changelog.md).

Historical changelogs and dated investigations describe the state recorded at the time; the workflow guides above are the best place to learn how OMG works today.

[Report a bug](https://github.com/omg-cli/omg/issues) with your version, platform, command, and redacted output. Report vulnerabilities privately using [SECURITY.md](../SECURITY.md).

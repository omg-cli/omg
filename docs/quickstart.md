---
title: Quickstart
sidebar_position: 2
description: Select a project runtime, run a task, and check environment drift
---

# Run a project with OMG

Use an existing Node.js project to select a runtime, run a task, and capture an environment record. This tutorial does not install system packages.

OMG is approaching beta. Start in a repository you trust, and use a disposable machine for package mutations. Project tasks execute repository code.

## Install OMG

Follow the [installation guide](./installation.md) for your platform. Release installation requires GitHub CLI for attestation verification. After installation, confirm that your shell finds the expected binary:

```bash
command -v omg
omg --version
omg --help
```

The commands print the binary path, version, and available commands. If the path is wrong or missing, fix `PATH` before continuing.

## Select the project runtime

From your Node.js project directory:

```bash
omg use node 22
omg which node
```

The first command installs Node.js if it is missing and changes OMG's selected version. The second prints the resolved runtime version. Choose a version supported by your project rather than changing an existing version requirement to match this example.

To select from an existing supported version file, run `omg use node` without a version. See [runtime detection](./runtimes.md) for supported files and precedence.

## Run a project task

Inspect the `scripts` object in your project's `package.json`. If it defines `build`, run:

```bash
omg run build
```

Expect the project's build output. A failed task makes OMG exit nonzero, but OMG does not preserve the task's exact exit code. `omg run` requires a task name. OMG does not invent a build task or replace dependency installation. Follow the project's instructions for installing JavaScript dependencies first.

## Record the environment

`omg env capture` writes `omg.lock` in the current directory. Review an existing lockfile before replacing it.

```bash
omg env capture
omg env check
```

The check compares the recorded environment with the current machine and reports drift. It exits nonzero when they differ. Review the lockfile before committing or sharing it because it contains environment inventory.

`omg env share` can publish the lockfile through GitHub Gist and requires a `GITHUB_TOKEN` environment variable. Sharing uploads data. `omg env sync <gist-url>` downloads and validates a lockfile, backs up a differing existing file, and checks drift. Neither sync nor check installs packages or runtimes.

## Add automatic switching

For directory-based runtime selection, follow [shell integration](./shell-integration.md). Add only the hook for your shell, and avoid conflicting hooks from other runtime managers.

## Inspect system packages

On a supported package backend:

```bash
omg search ripgrep
omg info ripgrep
omg install --dry-run ripgrep
```

On Arch, search includes AUR unless you pass `--no-aur`. Search results and timings depend on the repository state and enabled sources.

A dry run previews the requested change. It does not establish that package code is safe. To try an actual installation, use a recoverable machine and read [package operations](./packages.md), including backend-specific removal behavior and AUR review requirements.

## Explore the next workflow

- [Run tasks from other project types](./task-runner.md).
- [Manage Python, Rust, and other runtimes](./runtimes.md).
- [Share environment records with a team](./team.md).
- [Understand security reports and their limits](./security.md).
- [Resolve a failed command](./troubleshooting.md).

If the tutorial fails, [report the command and redacted output](https://github.com/PyRo1121/omg/issues), along with your OMG version and distribution.

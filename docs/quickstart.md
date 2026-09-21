---
title: Quickstart
sidebar_position: 2
description: Select a project runtime, run a task, and capture a working environment
---

# From zero to a working project

OMG gives a project one workflow for selecting a runtime, running its tasks, and recording the setup that worked. This quickstart takes a few minutes and uses an existing Node.js project as the example.

## 1. Install OMG

Follow the [installation guide](./installation.md) for your platform. Then verify that your shell can find the binary:

```bash
command -v omg
omg --version
omg --help
```

If `command -v omg` points to an older installation, fix `PATH` before continuing.

## 2. Select the project runtime

Change to a project directory and choose the version it expects:

```bash
omg use node 22
omg which node
```

`omg use` installs the runtime when needed and makes it the selected version for the project context. `omg which` shows the binary that will run. To let OMG read a supported version file instead, use `omg use node` without a version. See [runtime detection](./runtimes.md) for supported files and precedence.

## 3. Run the project

Run a task that the repository already defines. For a project with a `build` script in `package.json`:

```bash
omg run build
```

You can use the same command for common tasks such as `dev`, `test`, or `lint`:

```bash
omg run dev
omg run test
```

OMG detects the project runner and passes through its output. Install the project's dependencies according to its own instructions before running a task. The [task runner guide](./task-runner.md) covers other project types, including Cargo projects and Makefiles.

## 4. Capture a working environment

When the project is in a good state, record the environment so you can compare another machine or share the setup with a teammate:

```bash
omg env capture
omg env check
```

`omg env capture` writes `omg.lock` in the current directory. `omg env check` compares that record with the current machine and reports drift. Review the lockfile before committing or sharing it.

## Choose your next workflow

- [Manage runtimes automatically when you change directories](./shell-integration.md).
- [Search and install system packages](./packages.md).
- [Use existing mise project configuration](./mise-compatibility.md).
- [Share environment records with a team](./team.md).
- [Understand verification and security boundaries](./security.md).
- [Resolve a failed command](./troubleshooting.md).

If the quickstart does not match your project, [open an issue](https://github.com/omg-cli/omg/issues) with your OMG version, platform, command, and redacted output.

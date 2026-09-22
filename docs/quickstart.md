---
title: Quickstart
sidebar_position: 3
description: Choose a runtime for a project, run one of its tasks, and record the environment, in plain steps
---

# Run a project with OMG

**In plain words:** This page takes you from a finished installation to running a task in one of your own projects. It does not install system packages. It can download Node.js and write an environment record in the project folder.

This page shows you how to use OMG with a Node.js project you already have. You will choose the version of Node.js the project uses, run one of the project's own tasks, and save a record of the environment. You will not install system packages here.

**New to the terminal?** Read [Getting started](./getting-started.md) first. It explains the words used on this page, and [the glossary](./glossary.md) explains anything else.

Two things to know before you start:

- **OMG is approaching beta.** Commands and formats may still change.
- **Project tasks run code from your project folder.** Use a project you trust, and use a machine you can reinstall if you later change system packages.

## What you need first

- OMG installed. If it is not installed yet, follow [Installation](./installation.md) first.
- A Node.js project folder on your computer, with a `package.json` file inside it.
- An internet connection, because choosing a runtime version may download it.
- The GitHub CLI program (`gh`) if you still have to install OMG from a release download; the [installation guide](./installation.md) explains that part.

## Step 1: Check that OMG is installed

Type these three commands, one at a time. Press Enter after each one.

```bash
command -v omg
omg --version
omg --help
```

**What you should see:** the first command prints the folder that holds the `omg` program. The second prints a version number. The third prints the list of available commands.

If the first command prints nothing, or says `not found`, your computer cannot find the program yet. Follow the [installation guide](./installation.md) to fix your `PATH` before continuing. `PATH` is the list of folders your computer searches when you type a program's name; it is explained in [the glossary](./glossary.md).

## Step 2: Choose the project's Node.js version

In the terminal, go to your project folder. In this example the folder is named `my-project` and sits in your home folder. The `~` sign means your home folder, so type the path that matches your own folder:

```bash
cd ~/my-project
```

Then choose the Node.js version and check which one is active:

```bash
omg use node 22
omg which node
```

**What you should see:** the first command selects a Node.js 22 release, or installs one first if needed. The second prints the selected version, starting with the word `node`. It does not print the executable path.

Choose a version your project actually supports. Do not change the project's version requirement just to match this example. To let OMG read an existing project version file instead, run `omg use node` without a version number. [Runtime management](./runtimes.md) lists the supported files and their order.

## Step 3: Run one of the project's tasks

Open your project's `package.json` file in a text editor and find the `scripts` section. If it defines a task called `build`, run:

```bash
omg run build
```

**What you should see:** the output of the project's own build command.

Three limits are worth remembering:

- `omg run` always needs a task name. There is no default task.
- OMG does not invent a task that the project does not define, and it does not replace installing the project's dependencies. Follow the project's own instructions for installing JavaScript dependencies first.
- If the task fails, OMG exits with a failure (a nonzero exit code), but it does not pass on the task's exact exit code.

## Step 4: Record the environment

An environment record is a list of the runtime versions and packages that are present, with a fingerprint that lets OMG tell when they change.

> **Warning:** `omg env capture` writes a file called `omg.lock` in the current folder. If one already exists, the command replaces it. Look at the existing file before you replace it.

```bash
omg env capture
omg env check
```

**What you should see:** the first command reports that the environment state was captured and saved to `omg.lock`. The second compares the file with the current machine and reports drift. Drift means the two differ; the command then exits with a failure (a nonzero exit code).

Two limits to remember:

- Environment records need the Arch or Debian package system. On Fedora, these commands stop with a clear message instead of working.
- `omg env check` reports differences. It does not fix them.

An `omg.lock` file lists what is on your computer. **Look at it before you commit it to a repository or share it with anyone.**

## Step 5 (optional): Share or download an environment record

> **Warning:** sharing uploads the contents of your `omg.lock` to GitHub Gist. Anyone who has the link can read it, and an unlisted (secret) Gist is not encrypted.

```bash
omg env share
```

`omg env share` needs a GitHub token in an environment variable named `GITHUB_TOKEN`. It publishes the lock file as a Gist.

To download a record that someone shared with you, use `omg env sync` followed by the Gist address:

```bash
omg env sync https://gist.github.com/USER/GIST_ID
```

**What you should see:** the command downloads the file, checks that it is a valid `omg.lock`, keeps your previous copy as `omg.lock.backup` if the two differ, and then checks your machine for drift.

Neither `env sync` nor `env check` installs packages or runtimes.

## Step 6 (optional): Switch versions automatically when you change folders

For directory-based runtime selection, follow [shell integration](./shell-integration.md). Add only the hook for the shell you use, and avoid hooks from other runtime managers that do the same job.

## Step 7 (optional): Look at system packages

If your computer uses a supported package system (Arch, Debian, Ubuntu, Fedora, or Homebrew on macOS), you can also use OMG for software packages.

```bash
omg search ripgrep
omg info ripgrep
omg install --dry-run ripgrep
```

**What you should see:** the search lists matching packages, `omg info` shows one package's details, and the dry run prints what an installation would change and then changes nothing.

- On Arch, search includes the AUR (community build recipes) unless you add `--no-aur`.
- Search results and timings depend on the repository state and the sources you have turned on.
- A dry run only shows the plan. It does not prove that package code is safe.
- If you run `omg install` with no package name, OMG opens an interactive picker instead. It is not a way to install a project's dependencies.

To try a real installation, use a machine you can reinstall, and read [Package management](./packages.md) first. That page explains how removal works on each system and when AUR builds need your review.

## What OMG actually resolved

The steps above are short on purpose. Here is what each one did on your behalf, which is
what you need when the result is not what you expected.

```bash
omg which node    # prints the selected Node.js version
```

- **Runtime selection.** `omg use node 22` resolves a version request against the versions
  already installed; if the version is missing it downloads the official release, verifies
  it, extracts it under `versions/node/<version>` in your data directory, and updates the
  `current` link. `omg which node` then reports the selected version. When a project pin
  exists (`.node-version`, `.nvmrc`, `package.json`, `.tool-versions`), the shell hook
  selects the project's installed version when you enter the folder. The hook does not
  download a missing version.
- **Task execution.** `omg run build` inspects the current directory, chooses a task
  runner, and runs that project's command. If several runners define the same task,
  use `--using <ecosystem>` to choose one or `--all` to run each detected match.
  Arguments after `--` go to the underlying task. See [task runner](./task-runner.md)
  for detection rules and precedence.
- **Environment record.** `omg env capture` probes the registered runtimes and tools,
  collects the explicitly installed packages from your backend, normalizes both lists, and
  stores them with a schema version, a timestamp, and a SHA-256 fingerprint in `omg.lock`.
  `omg env check` recomputes the fingerprint and reports the differences, exiting non-zero
  when the machine no longer matches the record.

For the mechanisms behind these steps, see [Under the hood](./under-the-hood.md): socket
framing, cache freshness, backend query paths, the AUR gates, and what the audit chain does
and does not prove.

## If something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `omg: command not found` | Your computer cannot find the OMG program | Repeat the `PATH` step in [Installation](./installation.md), or open a new terminal window |
| `No omg.lock file found` | `omg env check` or `omg env share` needs a record first | Run `omg env capture` in the project folder |
| `Environment drift detected` | The record and the current machine differ | This is expected after you change something. Read the differences, then capture again if you accept them |
| The task stops with an error | The project's own command failed | Read the output above the error. OMG reports the failure but does not repeat the task's exact exit code |
| `failed to resolve active version` | No runtime version is selected yet | Run `omg use node 22`, or add a version file the project supports |
| `GITHUB_TOKEN environment variable not set` | The sharing step has no GitHub token | Create a token and set it for this terminal window only. Do not paste tokens into files you share |
| A checksum or provenance check fails while installing OMG | The download did not match its published proof | Stop. Do not turn the check off. Report it as described below |
| `omg use` stops with a message about the runtime or version | The name or version is not one OMG manages | Check [Runtime management](./runtimes.md) for supported names and versions |

## Where to go next

- [Getting started](./getting-started.md) if any term on this page was new to you.
- [Glossary](./glossary.md) for everyday-language definitions.
- [Run tasks from other project types](./task-runner.md).
- [Manage Python, Rust, and other runtimes](./runtimes.md).
- [Share environment records with a team](./team.md).
- [Understand security reports and their limits](./security.md).
- [Resolve a failed command](./troubleshooting.md).

If the tutorial fails, [report the command and its output](https://github.com/omg-cli/omg/issues), along with your OMG version and your Linux distribution or macOS version. Remove passwords, tokens, and private folder names before you post.

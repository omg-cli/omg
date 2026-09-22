---
title: Run project tasks
sidebar_position: 13
description: Find and run project build, test, and other tasks with OMG
---

# Run project tasks

`omg run` runs a named task from the project directory you are in. It can use scripts from several project file formats. A task runs code from that project, so review unfamiliar repositories before using it.

## What you need first

- [Install OMG](./installation.md) and open a terminal in your project directory.
- Install the project's normal build tools and dependencies. OMG may offer to install a missing runtime or enable a JavaScript package manager, but task detection does not install every dependency.
- If you need a term explained, see the [glossary](./glossary.md).

## Run a task

For a project that defines `build`, run:

```bash
omg run build
```

OMG prints the selected ecosystem and source file before it runs the task. To pass arguments to the task, put `--` before them:

```bash
omg run test -- --coverage
```

Task names can contain ASCII letters, digits, `-`, `_`, and `.`. A colon in a requested name, such as `test:watch`, is rejected by the current CLI. Run that script with its native tool instead.

## Project files OMG reads

OMG detects most tasks in the current directory. It does not search all subdirectories. The exception is mise configuration, which also reads ancestor directories.

| Project file | Tasks OMG discovers | Command it uses |
| --- | --- | --- |
| `package.json` | Entries in `scripts`, plus `install` when no install script exists | Selected npm, pnpm, Yarn, or Bun command |
| `deno.json` | Entries in `tasks` | `deno task` |
| `composer.json` | Entries in `scripts` | `composer run-script` |
| `Cargo.toml` | `build`, `test`, `check`, `run`, `clippy`, `fmt` | `cargo` |
| `Makefile` | Plain targets OMG can read from the file | `make` |
| `pyproject.toml` | `[tool.poetry.scripts]` entries | `poetry run` |
| `Pipfile` | `[scripts]` entries | `pipenv run` |
| `pom.xml` | `clean`, `compile`, `test`, `package`, `install` | `mvn` |
| `build.gradle` or `build.gradle.kts` | `build`, `test`, `run`, `clean` | `./gradlew` |
| Supported mise project files | Supported `[tasks]` declarations | Native OMG task execution through `sh` |
| `Taskfile.yml` or `Taskfile.yaml` | `list`; other names use the fallback path | `task` |
| `Rakefile` | `tasks`; other names use the fallback path | `rake` |

The Taskfile and Rakefile integrations do not parse their task lists. `omg run build` can still try `task build` or `rake build` when no discovered task has that name. The fallback can also try an executable with the requested name. Check the project file before relying on a fallback.

`deno.jsonc` is not read by the current task detector. For a JSONC-only project, use `deno task` directly.

## Choose between matching tasks

If the same task name exists in several project files, OMG normally chooses the highest-priority ecosystem. Rust ranks above JavaScript, Python, Go, Ruby, Java, PHP, mise, and Make. Ecosystems at the same priority can prompt in an interactive terminal. Without a terminal, an unresolved tie fails and asks you to choose.

Use `--using` to choose an ecosystem:

```bash
omg run test --using rust
```

You can set a preference in the project's `.omg.toml`:

```toml
[scripts]
test = "rust"
build = "node"
```

`--all` runs every detected match for one task name, one after another. If one fails, execution stops. `--all` and `--using` cannot be combined.

## Choose a JavaScript package manager

For `package.json`, OMG checks the `packageManager` field first. It then checks `bun.lockb`, `pnpm-lock.yaml`, `yarn.lock`, and `package-lock.json` or `npm-shrinkwrap.json`, in that order. With no marker, it uses npm. The current detector does not use `bun.lock` as a marker.

```json
{
  "packageManager": "pnpm@9.0.0",
  "scripts": { "build": "vite build" }
}
```

The field selects the manager name. OMG does not pin or install the exact `@9.0.0` version from that field. If pnpm or Yarn is missing, OMG may offer to enable it through Corepack. Check the tool version separately when exact reproducibility matters.

## Watch and parallel modes

```bash
omg run test --watch
```

Watch mode reruns a single task when watched files change. Stop it with Ctrl+C.

```bash
omg run build,test --parallel
```

Parallel mode takes a comma-separated list of task names. The CLI rejects conflicting combinations of `--watch`, `--parallel`, `--using`, and `--all`. See `omg run --help` for the accepted flags.
At most 16 task names can run in one parallel invocation. Each task receives
the extra arguments you pass after `--`.

## mise tasks

OMG reads layered mise project files, including supported local and selected-environment files. It accepts a string task or a table with `run`, `depends`, `dir`, `env`, `description`, and `hide` properties. Dependencies run once in declared order before the requested task. Missing dependencies and cycles fail before execution. Unsupported execution controls fail during discovery.

```toml
[tasks]
build = { run = "cargo build", depends = ["generate"] }
generate = "echo ready"
```

`omg run build --using mise` selects this task if another ecosystem also defines `build`. The task runs from the configuration file's project root unless `dir` sets a literal relative directory. See [mise compatibility](./mise-compatibility.md) for supported layers and limits.

## If something goes wrong

| What you see | What to check |
| --- | --- |
| Wrong ecosystem selected | Run with `--using`, or set `[scripts]` in `.omg.toml`. |
| Task not found | Check the supported project file in the current directory and the exact task name. |
| A different JavaScript manager runs | Check `packageManager` and lockfiles in the order above. |
| A runtime installation prompt appears | Review the project pin and requested version before accepting it. |
| A command fails after detection | Run the underlying project command to diagnose its dependencies and script. |

`omg run` has no `--list` option. Read the project's scripts or targets, or use its native listing command. `omg env capture` records an environment snapshot, not a complete dependency lock. Keep ecosystem lockfiles and normal build checks.

## Where to go next

- [Runtime management](./runtimes.md) explains version pins.
- [Shell integration](./shell-integration.md) explains directory-based switching.
- [Troubleshooting](./troubleshooting.md) has more diagnosis steps and support links.

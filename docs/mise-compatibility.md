---
title: mise project files
sidebar_position: 14
description: Use supported mise tool pins, environments, and tasks with OMG
---

# mise project files

If your project has mise configuration, OMG can read some of its tool pins, environment values, and tasks. You can keep those project files while using OMG's native runtime managers and `omg run`. OMG does not implement the full mise CLI, plugin system, or lockfile format.

## What you need first

- [Install OMG](./installation.md) and open a terminal in the project.
- Review project files before running tasks or sourcing environment scripts. These can execute repository-controlled code.
- Use the [glossary](./glossary.md) if terms such as runtime or shell are new to you.

## Select a runtime

OMG reads simple version requests in `[tools]` from supported mise TOML files:

```toml
[tools]
node = "22"
python = "3.12"
```

After installing those runtimes with `omg use node 22` and `omg use python 3.12`, use `omg which node` or `omg which python` to inspect selection. A version request such as `22` can select a matching installed release. It is not an exact patch pin.

OMG normalizes native aliases such as `nodejs` to `node`. It uses a single string pin per runtime. Version arrays, backend-qualified tool names, backend options, and mise plugins do not become native OMG installs. There is no automatic fallback to the mise executable.

A dedicated version file, such as `.node-version`, wins over a mise pin in the same directory. A nearer project's pin wins over a parent directory's pin. The shell hook selects installed versions only; it does not install missing ones.

## Configuration layers

OMG reads project configuration from the current directory and its ancestors. Within a directory, it reads supported grouped files and sorted `conf.d` fragments, then `mise.toml` and `.mise.toml`, then local overrides. Selected environment files load afterward. Later layers replace earlier values for the same key. A child directory wins over its ancestors.

Common files include `mise.toml`, `.mise.toml`, `mise.local.toml`, `.mise.local.toml`, `.config/mise/config.toml`, and `.mise/config.toml`. The loader also accepts the corresponding supported grouped local and selected-environment forms. It does not do an independent search for global or system mise configuration.

Set `MISE_ENV` to choose named layers for an explicit command:

```bash
MISE_ENV=test omg run test
```

On Bash or Zsh, that sets the environment variable for this command. A comma-separated value selects layers in order. Later names have higher priority, and the final occurrence of a repeated name is kept. Names may contain ASCII letters, digits, underscores, and hyphens. A misspelled or malformed selected file can make the command fail.

## Project environment

For explicit task execution, OMG reads supported `[env]` entries. Strings
and integers set values. `true` sets the string `true`, while `false` unsets
the value. Tables support `value`, `default`, `required`, `tools`, and
`redact`. The `[env._]` table supports `path`, `file`, and `source`
directives.

```toml
[env]
APP_MODE = "development"
OPTIONAL_FLAG = { default = "off" }

[env._]
file = ".env"
path = "bin"
```

Relative directive paths use the declaring configuration root. Environment files may use dotenv, JSON, or TOML. YAML files fail with a conversion message. JSON and TOML values must be flat scalar values. Missing required values and required files fail during explicit task execution.

`_.source` runs a project script when an explicit task environment is resolved. Review it before running a task. Automatic shell hooks read runtime pins but do not load `[env]`, read environment files, or run source scripts.

## Project tasks

OMG accepts shorthand string tasks and task tables with `run`, `depends`, `dir`, `env`, `description`, and `hide`. A `run` value may be a string or an array of strings. Commands run in sequence and stop at the first failure.

```toml
[tasks]
generate = "echo ready"
build = { run = "cargo build", depends = ["generate"] }
```

```bash
omg run build --using mise
```

Dependencies run once, in declared order, before the requested task. OMG checks for missing dependencies and cycles before it starts. Arguments after `--` go only to the requested task. Task-local environment values do not flow into dependencies. A task runs from its declaring configuration root by default; a literal `dir` changes that directory relative to the root.

Task names requested through `omg run` may contain only ASCII letters, digits, `-`, `_`, and `.`. The file parser may accept a dependency name that you cannot request directly because it contains a colon. Use a supported top-level name or the native mise command for that task.

OMG rejects unsupported execution properties instead of ignoring them. These include `task_config`, post-dependencies, conditional controls, custom shells, file tasks, dependency arguments or patterns, and templates in `run` or `dir`. Tasks run sequentially; the supported subset does not claim identical mise scheduling or visibility behavior.

## Check a project before migrating

1. Review local and selected-environment files in the project and its parent directories. These layers may now override the ordinary file.
2. Check the value of `MISE_ENV` in the terminal or CI job that will run the task.
3. Inspect `[env._]` directives and task bodies before executing them.
4. Run a harmless task first, then verify the selected runtime with `omg which <runtime>`.

Existing mise installations and `mise.lock` are not imported into OMG's version store. Keep mise available until you have checked the tasks, runtime pins, and environment behavior you use.

## If something goes wrong

| What you see | What to check |
| --- | --- |
| Wrong runtime version | Look for a nearer version file or later mise layer. |
| Missing file or required value | Check `[env]` and `[env._]` paths relative to the declaring root. |
| Unsupported task property | Run that task with mise, or change it to OMG's supported subset. |
| Task name rejected | Use only the CLI's allowed characters for a directly requested name. |
| A hook does not set an environment value | Hooks select runtime paths; explicit tasks resolve project environment values. |

For exact behavior, see [runtime management](./runtimes.md), [run project tasks](./task-runner.md), and [shell integration](./shell-integration.md). For an issue you cannot resolve, capture the command, relevant non-secret configuration, and error, then use the support paths in [troubleshooting](./troubleshooting.md).

---
title: Shell integration
sidebar_position: 12
description: Select installed runtime versions when you change directories
---

# Shell integration

A shell is the program that reads commands in your terminal. OMG can add a hook to Bash, Zsh, or Fish so a project selects its installed runtime versions when you enter its directory. The hook changes your shell's `PATH`, the list of directories it searches for commands.

## What you need first

- [Install OMG](./installation.md) so the `omg` command is available.
- Know which shell your terminal runs. If you are unsure, read [getting started](./getting-started.md) and the [glossary](./glossary.md).
- Check your shell startup file for an existing OMG hook before adding a line. A second hook can duplicate work.

## Add a hook

Add the line for your shell to its startup file, then open a new terminal.

| Shell | Startup file | Line to add |
| --- | --- | --- |
| Bash | `~/.bashrc` | `eval "$(omg hook bash)"` |
| Zsh | `~/.zshrc` | `eval "$(omg hook zsh)"` |
| Fish | `~/.config/fish/config.fish` | `omg hook fish | source` |

For example, after adding the Zsh line, open a new Zsh terminal and enter a project with a `.node-version` file. Run:

```bash
omg which node
```

Then run:

```bash
node --version
```

The second command should use the installed version selected for that project. If it does not, check the pin, installed versions with `omg list node`, and the shell's `PATH`. The hook selects installed versions; it does not download a missing runtime.

`omg hook <shell>` prints the hook text. It does not edit your startup file when used normally. To remove an OMG-owned line from a startup file, use the matching `--uninstall` form, then start a new shell:

```bash
omg hook zsh --uninstall
```

The uninstall command removes only recognized OMG hook lines and writes an
`.omg-backup` copy beside the startup file. It refuses to rewrite a
symlink-managed startup file; edit that file's managed source instead.

## How pins are selected

OMG checks the current directory first, then its parents. A nearer pin wins. Within one directory, dedicated version files win over mise project files. For example, `.node-version` wins over `.nvmrc`, and both win over a Node pin in `mise.toml`.

| Runtime | Version files read by the hook |
| --- | --- |
| Node.js | `.node-version`, `.nvmrc`, `package.json`, `.tool-versions` |
| Python | `.python-version`, `pyproject.toml`, `.tool-versions` |
| Go | `.go-version`, `go.mod`, `.tool-versions` |
| Rust | `rust-toolchain`, `rust-toolchain.toml`, `.tool-versions` |
| Deno | `.deno-version`, `.dvmrc`, `.tool-versions` |
| Other native managers | Their dedicated file, where supported, or `.tool-versions` |

OMG also reads supported `[tools]` pins from layered mise project files. See [runtime management](./runtimes.md) and [mise project files](./mise-compatibility.md) for the full list and precedence. A malformed current-directory pin does not run project code. The hook warns and leaves the base `PATH` in use. A malformed ancestor pin is skipped with a warning.

The hook changes runtime search paths when your directory changes or a prompt runs. It restores the prior base `PATH` before applying the next directory's pins. It does not load mise `[env]` entries, read environment files, or execute source scripts. Explicit `omg run` tasks can resolve those values.

## Completions

Completions suggest commands and values when you press Tab. These are separate from the runtime hook. OMG can install them for Bash, Zsh, Fish, PowerShell, and Elvish.

```bash
omg completions bash
```

Replace `bash` with your shell's name. Without `--stdout`, the command installs the generated file in a user location. Check its printed path and restart the shell. Use `--stdout` when you want to inspect or redirect the script:

```bash
omg completions zsh --stdout
```

Dynamic package suggestions depend on the backend and available package metadata. Completion is a convenience; it does not validate or install the selected package.

## Prompt counters

Bash and Zsh hooks also provide `omg-ec`, `omg-tc`, `omg-oc`, and `omg-uc` for explicit, total, orphan, and update counts. They read a daemon status snapshot when its size, format, owner, and five-minute age checks pass. Zsh caches values in the shell for up to 60 seconds. Bash reads the snapshot on each helper call. The Fish hook does not define these helpers; use `omg ec` and the other CLI count commands there.

A missing or rejected status snapshot can produce a fallback value. Treat prompt counters as status hints, not a fresh package audit.

## If something goes wrong

| What you see | What to do |
| --- | --- |
| Your old runtime remains active | Check that the hook line appears once in the correct startup file, then start a new shell. |
| A pin does not select a runtime | Check `omg list <runtime>`; the selected version must already be installed. |
| A different pin wins | Look for a nearer directory or a dedicated version file in the same directory. |
| Tab completion does not appear | Run `omg completions <shell>`, check the printed install path, and restart the shell. |
| Directory changes feel slow | Measure `omg hook-env -s zsh` with your shell's timing tool and compare under the same conditions. |

Do not delete daemon sockets or rewrite shell startup files as a first troubleshooting step. See [troubleshooting](./troubleshooting.md) for diagnosis and support.

## Where to go next

- [Runtime management](./runtimes.md) explains installation and pin formats.
- [Configuration](./configuration.md) explains local settings.
- [Run project tasks](./task-runner.md) explains explicit project execution.

---
title: Runtime management
sidebar_position: 11
description: Install and select supported language runtimes with OMG
---

# Runtime management

A runtime is the software a project uses to run or build code. OMG can install supported runtimes and select a version for a project. This page explains the commands, version files, and limits.

## What you need first

- [Install OMG](./installation.md) for a supported operating system and package backend.
- Open a terminal in the project you want to work on. See [getting started](./getting-started.md) and the [glossary](./glossary.md) if you need help with these terms.
- Check the project's version files before installing. A version request from an unfamiliar repository is untrusted input.

Runtime installation can download archives, invoke build tools, or require platform libraries. Requirements vary by runtime and platform. Installing OMG does not supply every compiler or system library a provider may need.

## Supported runtimes

The CLI has native managers for Node.js, Python, Go, Rust, Ruby, Java, Bun, Pi, Deno, Zig, .NET, Erlang, PHP, and Swift. It also has a curated tool registry exposed through the same `omg use` and `omg list` commands. An unknown name fails explicitly; OMG does not invoke a fallback version manager.

| Runtime | Project pin files |
| --- | --- |
| Node.js | `.node-version`, `.nvmrc`, `.tool-versions`, `package.json` |
| Python | `.python-version`, `pyproject.toml`, `.tool-versions` |
| Go | `.go-version`, `go.mod`, `.tool-versions` |
| Rust | `rust-toolchain`, `rust-toolchain.toml`, `.tool-versions` |
| Ruby | `.ruby-version`, `.tool-versions` |
| Java | `.java-version`, `.tool-versions` |
| Bun | `.bun-version`, `.tool-versions`, `package.json` |
| Deno | `.deno-version`, `.dvmrc`, `.tool-versions` |
| Pi | `.tool-versions` |
| Zig | `.zig-version`, `.tool-versions` |
| .NET SDK | `global.json`, `.tool-versions` |
| Erlang | `.tool-versions` |
| PHP | `.php-version`, `.tool-versions` |
| Swift | `.swift-version`, `.tool-versions` |

Supported `[tools]` entries in layered mise project files can also pin native runtimes. See [mise project files](./mise-compatibility.md). OMG uses its own installation directory and does not import installations from nvm, pyenv, rustup, or mise.

## Install or select a version

Run one named runtime at a time:

```bash
omg use node 22
```

If a matching version is already installed, OMG selects it. Otherwise, it installs it through that runtime's manager. A short request such as `22` or `3.12` can resolve to a matching release. Use a full version when you need an exact patch level. `latest`, `lts`, and channels such as Rust `stable` are moving requests; available selectors vary by provider.

Check what you have:

```bash
omg list node
```

```bash
omg which node
```

`omg list node --available` asks the provider for available versions. That may require network access. `omg which node` prints the resolved active version or says that none is set; it does not identify the source file.

To use the version detected from a project file, omit only the version:

```bash
omg use node
```

The runtime name is required. `omg use` without a name is not a valid command. `omg use node 22` does not edit `.node-version`, `.tool-versions`, or another project file. Edit and commit the pin separately if your team should use it.

To remove an installed version, give its exact version:

```bash
omg use node 22.10.0 --uninstall
```

Switch away from an active version before removing it. The command removes that version's installation, not a project pin file.

## Select versions by directory

Install the [shell hook](./shell-integration.md) to update the terminal's command search path when you change directories. The hook chooses installed versions. It does not run `omg use` or download a missing version.

OMG checks the current directory, then its parents. The nearest directory with a pin for a runtime wins. Within one directory, dedicated files are read before `.tool-versions`, `package.json`, and mise layers. For Node, that means `.node-version` takes priority over `.nvmrc`, then `.tool-versions`, then `package.json`. Within `package.json`, `engines` takes priority over `volta`. For Python, `.python-version` takes priority over `pyproject.toml`'s `[project]` `requires-python`.

A `.tool-versions` file can pin several runtimes:

```text
node 22.10.0
python 3.12.7
rust stable
```

Keep one line per runtime. If the same runtime appears twice, OMG uses the first line. A version requirement or major version is not an exact release pin. See the [editable example](../examples/.tool-versions).

OMG puts a selected installation's binary directory on `PATH`. Companion commands shipped by a runtime, such as `npm` or `cargo`, come from that installation. OMG does not reimplement their package managers. Global packages installed into one runtime version may be absent after switching versions; install project dependencies locally or manage globals per version.

## Rust toolchain notes

Only one Rust toolchain mutation runs at a time in an OMG data directory. If another operation is active, wait and retry. The lock covers updates, removal, and activation. Do not delete `versions/rust/.mutation.lock`; the file's presence alone does not mean a mutation is active.

An incremental Rust component or target addition must match the installed toolchain's recorded compiler release, including a nightly commit. If upstream has changed, OMG rejects the incremental addition before replacing files. Retry full setup to refresh the toolchain first. This does not undo a preceding channel refresh. Legacy metadata can be read, but a missing release identity requires a complete reinstall before incremental additions. Matching the compiler identity does not prove the full manifest is identical.

## Integrity and storage

Provider verification differs. Native archive managers use their supported published checksum or release-digest paths. Pi installation delegates to npm with `--global --ignore-scripts` and checks the installed version; it does not use OMG's archive-digest path. npm's registry and integrity settings apply. Do not bypass a failed download or checksum check to make an installation succeed.
Official runtime downloads use HTTPS with certificate validation. The shared
HTTP client rejects an HTTPS-to-HTTP redirect. npm-managed installation
follows npm's own transport settings.

OMG stages archive extraction before publishing a version directory. Its data directory is normally under `~/.local/share/omg` on a non-root Unix account, but XDG and privilege rules can change the path. Use [configuration](./configuration.md) to find the current paths. User-local runtime storage does not remove platform prerequisites or grant sandbox isolation to code run with a runtime.

## If something goes wrong

| What you see | What to check |
| --- | --- |
| `omg use node` finds no version | Add a supported project pin or give an explicit version. |
| The shell still runs an older executable | Install the hook, start a new shell, and inspect `PATH` order. |
| A pin has no effect | Check `omg list <runtime>`; automatic switching needs an installed match. |
| An install fails | Keep the provider error, check network access and disk space, and consult its platform requirements. |
| A global package disappears after switching | Check the selected runtime version and install that package per version or in the project. |

## Where to go next

- [Shell integration](./shell-integration.md) explains automatic switching.
- [Run project tasks](./task-runner.md) explains task execution with selected runtimes.
- [Troubleshooting](./troubleshooting.md) has diagnosis and support paths.

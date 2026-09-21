---
title: Shell Integration
sidebar_position: 12
description: Hooks, completions, and PATH management
---

# Shell Integration

**In plain words:** One small addition to your shell start-up file lets OMG select the right language version automatically when you enter a project folder. This page has the exact line for each shell, how to check it works, and how to remove it.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

**Hooks, Completions, and PATH Management**

This guide covers OMG's shell integration features including the shell hook, completions, and ultra-fast shell functions.

---

## Overview

OMG provides deep shell integration that:

1. **Automatically updates PATH** when you change directories
2. **Detects version files** and activates the correct runtime
3. **Provides shell completions**, whose behavior depends on shell setup and available metadata
4. **Exposes ultra-fast functions** for shell prompts

---

## Shell Hook Installation

### What the Hook Does

The shell hook:

- Runs on every directory change (`cd`)
- Runs on every prompt (to catch `pushd`, `popd`, etc.)
- Detects version files (`.nvmrc`, `.python-version`, etc.)
- Prepends correct runtime `bin` directories to PATH
- Provides fast package count functions

### Installation by Shell

#### Zsh

Add to `~/.zshrc`:

```bash
eval "$(omg hook zsh)"
```

Reload:

```bash
source ~/.zshrc
# or
exec zsh
```

#### Bash

Add to `~/.bashrc`:

```bash
eval "$(omg hook bash)"
```

Reload:

```bash
source ~/.bashrc
# or
exec bash
```

#### Fish

Add to `~/.config/fish/config.fish`:

```fish
omg hook fish | source
```

Reload:

```fish
source ~/.config/fish/config.fish
# or
exec fish
```

### Verifying Installation

```bash
# Test hook output
omg hook zsh

# Check if hook is active
type _omg_hook

# Test version detection
cd /path/to/project/with/.nvmrc
echo $PATH | grep omg
```

---

## How Version Detection Works

### Detection Order

When you enter a directory, OMG checks for version files in this order:

1. **Current directory**
2. **Parent directories** (walking up to filesystem root)

If no version file matches, the shell hook restores the base PATH.

### Supported Version Files

| File | Runtime | Priority |
| ------ | --------- | ---------- |
| `.node-version` | Node.js | 1 (highest) |
| `.nvmrc` | Node.js | 2 |
| `.bun-version` | Bun | 1 |
| `.python-version` | Python | 1 |
| `pyproject.toml` | Python | 2 (`[project.requires-python]`) |
| `.ruby-version` | Ruby | 1 |
| `.go-version` | Go | 1 |
| `go.mod` | Go | 2 |
| `.java-version` | Java | 1 |
| `rust-toolchain` | Rust | 1 |
| `rust-toolchain.toml` | Rust | 2 |
| `.deno-version` | Deno | 1 |
| `.dvmrc` | Deno | 2 |
| `.zig-version` | Zig | 1 |
| `global.json` | .NET SDK | 1 |
| `.php-version` | PHP | 1 |
| `.swift-version` | Swift | 1 |
| `.tool-versions` | Multiple | Universal multi-tool pin |
| `package.json` | Node/Bun | Engines / Volta |
| `mise.toml`, `.mise.toml` | Multiple | Universal `[tools]` pin |

### Version File Formats

#### Simple Version Files

`.nvmrc`, `.python-version`, `.go-version`, etc.:

```
20.10.0
```

Or with `v` prefix:

```
v20.10.0
```

Or aliases (Node.js):

```
lts/*
lts/hydrogen
```

#### rust-toolchain.toml

```toml
[toolchain]
channel = "stable"  # or "nightly" or "1.75.0"
components = ["rustfmt", "clippy"]
targets = ["wasm32-unknown-unknown"]
profile = "minimal"
```

Or simple `rust-toolchain` file:

```
stable
```

#### .tool-versions (asdf format)

```
node 20.10.0
python 3.12.0
rust stable
go 1.21.0
```

#### package.json

```json
{
  "engines": {
    "node": ">=18 &lt;21",
    "bun": ">=1.0"
  },
  "volta": {
    "node": "20.10.0",
    "bun": "1.0.25"
  }
}
```

Priority: `engines` > `volta`

---

## Prompt counters

Bash and Zsh hooks define package-count helpers. They read `omg.status` beside the daemon socket after checking size, magic, version, ownership, and a five-minute timestamp. Fish's generated hook does not define these helpers. Use `omg ec` there, or call the CLI from the prompt.

### Shell helpers

Zsh keeps `omg-ec`, `omg-tc`, `omg-oc`, and `omg-uc` in shell variables and refreshes them at most every 60 seconds. Until the first successful read, those variables are `0`. Bash defines the same short names as aliases of the file readers below, so each prompt call reads the file.

| Function | Returns |
| --- | --- |
| `omg-ec` | Explicit package count |
| `omg-tc` | Total package count |
| `omg-oc` | Orphan count |
| `omg-uc` | Updates count |
| `omg-explicit-count` | Explicit count read from `omg.status`, or `omg explicit --count` when the file is rejected |
| `omg-total-count` | Total count read from `omg.status`, or `0` when the file is rejected |
| `omg-orphan-count` | Orphan count read from `omg.status`, or `0` when the file is rejected |
| `omg-updates-count` | Update count read from `omg.status`, or `0` when the file is rejected |

### Using in Prompts

#### Zsh Prompt

```bash
# In ~/.zshrc
PROMPT='[📦 $(omg-ec)] %~$ '

# Or with colors
PROMPT='%F{cyan}[$(omg-ec) pkgs]%f %~$ '

# Full example with git
PROMPT='%F{green}%n@%m%f %F{blue}%~%f $(git_prompt_info)[📦 $(omg-ec)]$ '
```

#### Bash Prompt

```bash
# In ~/.bashrc
export PS1='[\w] $(omg-ec) pkgs$ '

# With colors
export PS1='\[\e[36m\][$(omg-ec) pkgs]\[\e[0m\] \w$ '
```

#### Fish prompt

The generated Fish hook does not define `omg-ec`. Read the count from the CLI:

```fish
function fish_prompt
    echo -n (omg ec)" pkgs "
    set_color blue
    echo -n (prompt_pwd)
    set_color normal
    echo '$ '
end
```

### Performance Comparison

Cached prompt values avoid a fresh query but can be stale. Compare fresh queries separately, with the same backend and cache conditions. See [benchmark evidence](../benchmarks/README.md); this guide establishes no timing thresholds.

---

## Shell Completions

### Installation

#### Zsh

```bash
# Create completions directory
mkdir -p ~/.zsh/completions

# Generate completions (note --stdout: bare `omg completions <shell>` installs instead of printing)
omg completions zsh --stdout > ~/.zsh/completions/_omg

# Add to fpath in ~/.zshrc (if not already)
fpath=(~/.zsh/completions $fpath)
autoload -Uz compinit && compinit

# Rebuild completion cache
rm ~/.zcompdump
compinit
```

#### Bash

```bash
# System-wide
omg completions bash --stdout | sudo tee /etc/bash_completion.d/omg >/dev/null

# Or user-only
omg completions bash

# Source immediately
source /etc/bash_completion.d/omg
```

#### Fish

```bash
# User completions
omg completions fish

# System-wide
omg completions fish --stdout | sudo tee /usr/share/fish/vendor_completions.d/omg.fish >/dev/null
```

### Completion Features

OMG provides intelligent completions for:

- **Commands**: All subcommands with descriptions
- **Package names**: From the daemon index when that index is available
- **Runtime versions**: Installed and available versions
- **Options**: All flags with descriptions

### Fuzzy Matching

OMG uses Nucleo for ultra-fast fuzzy matching:

```bash
omg i frfx<TAB>
# Completes to: firefox
```

---

## Hook behavior

`omg hook bash`, `omg hook zsh`, and `omg hook fish` print the scripts below. The printed script is the source of truth. Each hook saves the original `PATH`, restores environment changes from the previous directory, and calls `command omg hook-env` so a shell function named `omg` cannot shadow the binary. An interactive shell can also start the daily update-notice check.

Zsh registers `_omg_hook` on `precmd_functions` and `chpwd_functions`, then refreshes its in-shell counter cache at most every 60 seconds. Bash registers `_omg_hook` on `PROMPT_COMMAND`, including when that variable is an array. Bash counter helpers read the status file on each call. Fish registers `_omg_hook` on `PWD` and `fish_prompt`.

The generated hook fills in the status path as the daemon socket's sibling, `omg.status`. Zsh and Bash accept the file only when it is a regular, user-owned, 32-byte snapshot with magic `OMGS`, version 1, and a timestamp no older than five minutes.

---

## Manual PATH Management

If you prefer manual control over PATH:

### Without Hook

```bash
# Manually add runtime paths
export PATH="$HOME/.local/share/omg/versions/node/current/bin:$PATH"
export PATH="$HOME/.local/share/omg/versions/python/current/bin:$PATH"
export PATH="$HOME/.local/share/omg/versions/go/current/bin:$PATH"
export PATH="$HOME/.local/share/omg/versions/rust/current/bin:$PATH"
```

### Project-Specific

```bash
# Add to project's .envrc (if using direnv)
export PATH="$HOME/.local/share/omg/versions/node/20.10.0/bin:$PATH"
```

### Check Active Versions

```bash
# See what's in PATH
echo $PATH | tr ':' '\n' | grep omg

# Check symlinks
ls -la ~/.local/share/omg/versions/node/current
```

---

## Configuration Options

### PATH Hooks

OMG uses shell hooks for runtime switching:

- PATH is updated on directory changes.
- No wrapper or shim executable layer is installed.
- Bash, Zsh, and Fish hooks are selected explicitly with `omg hook <shell>`.

### Runtime Resolution

Shell hooks resolve only OMG's native runtime installations. Unknown pins do not add anything to `PATH`.

---

## Troubleshooting

### Hook Not Running

```bash
# 1. Check hook is in shell config
grep "omg hook" ~/.zshrc

# 2. Verify hook works
omg hook zsh | head -20

# 3. Check function exists
type _omg_hook

# 4. Force reload
exec zsh
```

### Wrong Version Active

```bash
# 1. Check version files
ls -la .nvmrc .python-version .tool-versions

# 2. Check what OMG detects
omg which node

# 3. Check PATH order
echo $PATH | tr ':' '\n' | head -10
# OMG paths should be first

# 4. Force switch
omg use node 20.10.0
```

### Slow Directory Changes

```bash
# 1. Ensure daemon is running
omg status

# 2. Check hook-env timing
time omg hook-env -s zsh
# Record the result and compare against your own baseline.

# 3. If slow, the daemon may be down
omg daemon
```

### Completions Not Working

```bash
# Zsh
rm ~/.zcompdump
omg completions zsh --stdout > ~/.zsh/completions/_omg
compinit

# Check fpath
echo $fpath | tr ' ' '\n' | grep completions
```

---

## Performance Tips

### 1. Keep Daemon Running

```bash
# Start daemon on login
echo "omg daemon &" >> ~/.zprofile

# Or use systemd
systemctl --user enable omgd
```

### 2. Use Cached Functions in Prompts

```bash
# Fast (cached)
PROMPT='$(omg-ec) pkgs$ '

# Avoid (hits binary each time)
PROMPT='$(omg explicit --count) pkgs$ '
```

### 3. Minimize Version Files

Only place version files in project roots, not deeply nested directories.

### 4. Combine with Starship/Powerlevel10k

These prompt themes have built-in version display. Combine with OMG:

```bash
# OMG handles PATH, Starship handles display
eval "$(omg hook zsh)"
eval "$(starship init zsh)"
```

---

## See Also

- [Quick Start](./quickstart.md) — Initial setup
- [Configuration](./configuration.md) — Shell and runtime settings
- [Runtime Management](./runtimes.md) — Version file details
- [Troubleshooting](./troubleshooting.md) — Common issues

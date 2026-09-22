---
title: Update notices
sidebar_position: 37
description: How OMG tells you a newer release exists, and how to silence it
---

# Built-in update notices

**In plain words:** after a command finishes, OMG can tell you that a newer release exists.
This page explains when that check runs, what it does and does not do, and how to switch it
off.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

The notice is a convenience, and it behaves like one: a cached string compared against the
version you are running. It is never the authority for an installation.

## What you see, and when

```text
OMG 0.1.223 is available (installed: 0.1.222). Update with your package manager or `omg self-update`. Notes: https://github.com/omg-cli/omg/releases/tag/v0.1.223
```

- On Unix, a **successful interactive command** can print it after its own output. A failed command
  never prints a notice and never changes its exit status.
- A shell integration installed with `omg hook bash`, `omg hook zsh`, or `omg hook fish` can
  show the same notice in an interactive terminal. The hook is not required: notices work
  without it.
- The **first eligible command** starts a background check; a later command can display the
  result, because the foreground process only reads local state.

## When a notice is suppressed

```bash
# These never show a notice:
echo hi | omg status      # piped output
omg status --json         # JSON output
omg status --quiet        # quiet mode
omg --help                # help and completion protocols
omg self-update           # the updater itself
```

CI sessions and root sessions stay silent as well. A notice is possible only when the run is
interactive, successful, and not already handled by one of those cases.

## How the check works

- The foreground process reads a small cache file and compares versions locally; it does not
  block on the network.
- A separate background process has **at most three seconds** to fetch the same HTTPS release
  marker that `omg self-update` uses. Failures are silent, and offline use is unaffected.
- Checks and notices happen **at most once per day per user cache**, and failed network
  attempts count against that limit, so a broken connection cannot cause a retry loop.
- Cached results older than **seven days** are ignored.
- Only strictly newer, final releases are advertised: a version older than the installed
  build, a pre-release, or a version with build metadata is not shown.
- The request sends no install identifier and no telemetry. The HTTPS server necessarily sees
  normal request and network metadata.
- The cache file is opened symlink-safely and is bounded in size; unsafe or unreadable state is
  ignored rather than followed.

## Where the state lives

```bash
# The notice cache, normally under ~/.cache/omg.
ls -l "${XDG_CACHE_HOME:-$HOME/.cache}/omg/update-notice.json"
```

`OMG_CACHE_DIR` overrides the location. The file holds the last check time, last notice time,
and last version seen. It is not required for OMG to work. A damaged copy can be removed so the next
eligible command recreates it.

## Turn it off

```bash
# Bash or Zsh — add to your shell configuration, before the OMG hook if you use one.
export OMG_NO_UPDATE_CHECK=1
```

```fish
# Fish
set -gx OMG_NO_UPDATE_CHECK 1
```

Remove the variable to enable the feature again. Silent modes above still apply, so the
variable only matters for interactive use.

## Limits

- **It never installs anything.** No download or replacement happens because of a notice;
  direct installations update with `omg self-update`, and package-managed installations update
  through their package manager.
- **It is best effort.** A missed check, an offline machine, or a stale cache means no notice,
  not a broken installation.
- **It is not a security signal.** The notice compares version strings; it carries no
  advisory information. Vulnerability status comes from `omg audit`, whose scope is documented
  in [security](./security.md).
- **Silence is not failure.** Nothing about your installation changes when notices are off.

## Where to go next

- [Installation](./installation.md) for the update and uninstall procedures themselves.
- [Release notes](https://github.com/omg-cli/omg/releases) for what a specific release changed.
- [Configuration](./configuration.md) for cache and config locations.

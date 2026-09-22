---
title: Terminal dashboard
sidebar_position: 41
description: Inspect OMG state in a terminal
---

# Terminal dashboard

**In plain words:** OMG includes a text-based dashboard for looking at your system instead of typing commands. This page explains how to open it, how to move around, and how to leave it.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

```bash
omg dash
```

The dashboard presents available package, runtime, security, activity, and team data. Availability depends on the backend, daemon, and configured services. An empty or unavailable view is not evidence of zero vulnerabilities or a compliant fleet.

## What each view is for

```bash
omg dash     # opens the dashboard; the alias `omg d` is the same command
```

The six views are switched with `1` to `6` or `Tab`:

| Key | View | Shows |
| :--- | :--- | :--- |
| `1` | Dashboard | Package counts, security summary, and system overview |
| `2` | Packages | Search results, with selection and a confirmation step before anything changes |
| `3` | Runtimes | Installed runtime versions and the one currently selected |
| `4` | Security | Scan findings and the classification assigned to them |
| `5` | Activity | Recorded transactions from the history log |
| `6` | Team | Shared environment state when this machine is part of a team workspace |

The keys are defined in `src/cli/tui/app.rs` and `src/cli/tui/mod.rs`.

## Navigation

- `1` through `6`: Dashboard, Packages, Runtimes, Security, Activity, Team.
- `Tab` / `Shift+Tab`: change views.
- Up/Down or `k` / `j`: move the selection.
- `/`: enter package search from Packages.
- Enter: act on the selected item or search state.
- Escape: leave search or the current interaction.
- `r`: request refresh outside text entry.
- `q`: quit outside text entry.
- `Ctrl+C`: quit, including during text entry.
- `u`, `c`, `o` on Dashboard: ask to update packages, clean package caches,
  or remove orphans. Enter confirms and Escape cancels.
- `a` on Security: run a security audit.

In search mode, character keys are text input rather than global shortcuts. Review the displayed action before confirming anything that could change state.

## Refresh and evidence

The application loop checks local and daemon data every five seconds. Remote
team data refreshes at most every five minutes while the Team view is open.
Individual retrieval can take longer. Manual refresh does not imply
instantaneous retrieval. Counts and timestamps reflect available observations,
not a promise of complete package or account coverage.

Security grades are classifications, not signature receipts. Activity is not a complete audit of native package-manager operations. See [security](./security.md) and [history](./history.md).

## Implementation

Application state and most key handling live in `src/cli/tui/app.rs`.
Actions, refresh scheduling, and terminal lifecycle live in
`src/cli/tui/mod.rs`. Rendering is in `src/cli/tui/ui.rs`.

## Troubleshooting

Use a terminal with the expected capabilities and a UTF-8 locale. Do not force an incorrect `TERM` value. If an exited process leaves terminal settings broken, `reset` or `stty sane` can restore them.


## Limits

- **A view can be empty for several reasons.** The dashboard only renders what the backend,
  the daemon, and any configured service actually return. An empty Security or Team view is
  not evidence of a clean machine or a compliant fleet.
- **The dashboard never decides for you.** Package actions ask for confirmation, and the same
  policy, review, and privilege rules apply as on the command line. Nothing in the TUI
  bypasses [policy](./security.md) or AUR review.
- **Refresh is periodic, not live.** The loop re-checks after five seconds and a slow backend
  can take longer, so treat displayed numbers as the most recent observation.
- **Keys can change between releases.** `src/cli/tui/app.rs` in the release you installed is
  the authority; the table above documents the current build.

## Where to go next

- [Getting started](./getting-started.md) if you have not used a terminal-based interface before.
- [Status and health](./cli.md) for the equivalent non-interactive commands.
- [Under the hood](./under-the-hood.md) for where the displayed data comes from.

Record terminal name, dimensions, OMG version, backend, and the failing interaction. Redact account data from screenshots. Do not start another daemon, clear history, or delete sockets just because a view is unavailable. See [troubleshooting](./troubleshooting.md).

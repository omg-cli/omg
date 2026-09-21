---
title: Terminal Dashboard
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

## Navigation

- `1` through `6`: Dashboard, Packages, Runtimes, Security, Activity, Team.
- `Tab` / `Shift+Tab`: change views.
- Up/Down or `k` / `j`: move the selection.
- `/`: enter package search from Packages.
- Enter: act on the selected item or search state.
- Escape: leave search or the current interaction.
- `r`: request refresh outside text entry.
- `q`: quit outside text entry.

In search mode, character keys are text input rather than global shortcuts. Review the displayed action before confirming anything that could change state.

## Refresh and evidence

The application loop checks for periodic refresh after five seconds; individual data retrieval can take longer. Manual refresh does not imply instantaneous retrieval. Counts and timestamps reflect available observations, not a promise of complete package or account coverage.

Security grades are classifications, not signature receipts. Activity is not a complete audit of native package-manager operations. See [security](./security.md) and [history](./history.md).

## Implementation

The current source uses ratatui 0.30 with its crossterm backend and crossterm 0.29. Application state and key handling live in `src/cli/tui/app.rs`; rendering is in `src/cli/tui/ui.rs`; terminal lifecycle is in `src/cli/tui/mod.rs`. These source files, not copied pseudocode, define the implementation.

## Troubleshooting

Use a terminal with the expected capabilities and a UTF-8 locale. Do not force an incorrect `TERM` value. If an exited process leaves terminal settings broken, `reset` or `stty sane` can restore them.

Record terminal name, dimensions, OMG version, backend, and the failing interaction. Redact account data from screenshots. Do not start another daemon, clear history, or delete sockets just because a view is unavailable. See [troubleshooting](./troubleshooting.md).

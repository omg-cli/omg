---
title: Caching and indexing
sidebar_position: 32
description: In-memory and persistent caching strategies
---

# Caching and indexing

**In plain words:** OMG keeps short-lived copies of information it has already looked up,
so repeating a command is faster. This page explains what is stored, where it lives, how
long it stays valid, and what is safe to delete.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

These three stores answer different questions. All are derived data; back up
history and your installed runtimes separately.

## The three tiers

| Tier | Where | Lifetime | Read by | Safe to delete? |
| :--- | :--- | :--- | :--- | :--- |
| In-memory cache | Inside the `omgd` process | Process lifetime, bounded eviction | Daemon-served queries | Yes — stopping the daemon discards it |
| JSON status snapshot | `~/.local/share/omg/status-cache.json` (or `OMG_DAEMON_DATA_DIR`) | Rewritten by each background refresh | Tooling that needs structured status | Yes — it is derived data |
| Binary status snapshot | `omg.status`, beside the socket in the session runtime directory | Rewritten each refresh; accepted only when ≤ 5 minutes old | `omg ec`, `omg tc`, `omg oc`, `omg uc` | Yes — it is derived data |

```bash
# The two files you can inspect directly, with the counters that read the binary one.
omg daemon-status                                   # resolved socket and daemon state
ls -l "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/omg.status"
omg ec                                              # explicitly installed packages
omg tc                                              # total installed packages
omg oc                                              # orphan candidates
omg uc                                              # updates available
```

Transaction history, the hash-chained audit log, and installed runtimes share the data
directory but are **not** caches: see [history](./history.md) and
[security](./security.md) before removing anything.

## What the binary snapshot contains

`omg.status` is a fixed 32-byte record. Shell hooks can read it without
starting an OMG process or querying a package database:

```text
offset  size  field
0       4     magic 0x4F4D4753 ("OMGS")   ← identifies the file and its byte order
4       4     format version              ← bumped when the layout changes
8       16    four u32 counts: total, explicit, orphan, updates-available
24      8     unix timestamp, seconds     ← the freshness check reads this
```

A counter accepts the file only when it is a regular file, owned by you, exactly the
expected size, and no older than **five minutes** (`FAST_STATUS_FRESHNESS_SECS = 300` in
`src/core/fast_status.rs`). Anything else silently falls back to the slower CLI path, which
is why a counter value can change after a background refresh.

The JSON snapshot is published atomically: a same-directory temporary file, `fsync`, then a
rename, with owner-only permissions. A reader therefore sees either the previous complete
snapshot or the new one, never a half-written file.

## How a query picks a path

1. The CLI asks the daemon when it is running. A hit returns immediately from memory.
2. A miss searches the daemon's in-memory index and, when the command needs them, the native
   databases and remote sources.
3. Without a daemon, the query takes the direct backend path. The paths can
   briefly disagree if their data was refreshed at different times.

```bash
omg search ripgrep --no-aur    # skip the network-backed AUR lane entirely
omg status --fast              # counts only, skipping the slower dependency scan
```

Real-world mirrors are also probed concurrently: the sync path races mirror `HEAD` requests
with a bounded timeout (`MIRROR_RACE_TIMEOUT_MS` in `src/package_managers/parallel_sync.rs`)
and uses the first that answers, rather than trying each mirror in turn.

## What is safe to remove

- **In-memory cache:** nothing to remove; it disappears with the process.
- **`status-cache.json` and `omg.status`:** derived data. They refill on refresh.
  `omg clean --cache` cleans package archives, not these status snapshots.
  Do not delete a whole data or cache directory to reset a snapshot: it can
  contain history, installed software, or artifacts needed for rollback.
- **Search indexes:** rebuilt from the native package databases, so they are never the
  authority.
- **Never:** `history.json`, the audit log, or the runtime versions directory. Those are
  durable records and installed software, not cache entries.

## Limits

- **A hit is not the cost of the command.** A cached search still pays for process start,
  argument parsing, rendering, and any post-processing; measure the whole command before
  treating a cache as a speed claim.
- **Snapshots lag reality.** A refresh runs every five minutes, so a prompt counter can be up
  to a few minutes behind a package change. It is a display convenience, not a transaction
  record.
- **A stale or rejected file is not an error.** If ownership, size, or age fails the check,
  the CLI counters take their fallback path. The shell hook may print zero for some
  counters when its snapshot is unavailable; use `omg status` for a fresh check.

## Where to go next

- [Under the hood](./under-the-hood.md) for the same rules in context with the rest of the runtime.
- [Package search](./package-search.md) for how the two search lanes interact.
- [Daemon](./daemon.md) for the process that owns these files.
- [History and rollback](./history.md) for the records you must not delete.

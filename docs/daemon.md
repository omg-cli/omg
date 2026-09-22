---
title: Daemon Internals
sidebar_position: 31
description: Background service lifecycle, IPC, and state management
---

# Daemon Internals (omgd)

**In plain words:** the daemon is a small helper program that stays in the background so
repeat commands answer faster. It is optional: OMG works without it.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

The daemon keeps derived package and status data warm for repeated queries. Package
transactions run through the CLI and its selected backend. Most commands still work
without `omgd`; the daemon-backed metrics command is an exception.

```bash
omg daemon                  # start it detached in the background
omg daemon --foreground     # run it in this terminal so you can read its output
omg daemon-status           # resolved socket, ownership, and whether a process answers
```

## Which commands need it

| Command | Without a running daemon |
| :--- | :--- |
| `omg search`, `omg info`, `omg install`, `omg update`, `omg remove` | Work through the direct backend path |
| `omg ec`, `omg tc`, `omg oc`, `omg uc` | Work: use a fresh status file when available, then the daemon or direct package data |
| `omg audit scan` | Works through a direct cold scan; the daemon path reuses warm package and vulnerability state |
| Unix SOC 2 export | Runs its vulnerability scan directly if the daemon is unavailable; it still needs a supported system SBOM backend |
| `omg metrics` | Fails explicitly; it is daemon-backed |
| `omg audit sbom` | Works with a supported system inventory and advisory source independently of daemon state (Arch, Debian, Ubuntu, or Fedora) |

## Startup, one instance at a time

Before it touches the socket, the daemon claims an exclusive `flock` on its own lock file.
The claim is held for the process lifetime and released by drop, so a crashed daemon does
not leave a permanent lock behind. If another process already answers on the socket, startup
stops with a message naming that socket instead of starting a second instance:

```text
Daemon is already running and responding on /run/user/1000/omg.sock
```

```bash
# The order the socket path is resolved in (first match wins):
#   1. $OMG_SOCKET_PATH
#   2. $XDG_RUNTIME_DIR/omg.sock
#   3. /run/user/<uid>/omg.sock
#   4. /tmp/omg-<uid>/omg.sock
#   5. a private <data-dir>/run/omg.sock when the /tmp fallback exists but is unsafe
omg daemon-status
```

The socket is bound mode `0600` and its parent directory mode `0700`; both ends revalidate
that the parent is a real directory owned by you with no group or world bits. A stale socket
file is removed on startup, but only after those checks pass. See [IPC](./ipc.md) for the
frame format and the message families.


## State it holds

- **In-memory cache (`moka`):** recent search results, package details, and system status,
  with bounded eviction so memory does not grow without limit.
- **JSON status snapshot:** versioned, published with a same-directory temporary file,
  `fsync`, and atomic rename, so a reader sees a complete document or the previous one.
- **Package index:** built from the official repository databases; the native databases stay
  the authority, so the index is disposable.
- **Binary status snapshot:** the fixed 32-byte record read by the prompt counters. See
  [cache](./cache.md) for its layout and freshness rule.

**Limit:** all cached package and status state is derived. The daemon does not own package
transactions or transaction history. It can append best-effort security events to the audit
log; see [security](./security.md#audit-logging) for what that log proves.

## Background refresh

A worker thread re-runs the "vital signs" pass every five minutes without blocking requests:

```bash
omg status --fast    # the cached counts the worker maintains, without the full scan
```

Each pass refreshes the package counts, probes the installed runtime versions, incorporates
advisory data when the backend supports it, and rewrites both snapshots. Between passes, a
prompt counter can be a few minutes behind a package change.

## Handling requests

Each connection is handled by its own asynchronous task, so a slow dependency resolution
does not block other callers. Requests route by kind:

| Kind | Handled by |
| :--- | :--- |
| Package queries | The in-memory index or selected package backend |
| Security work | The vulnerability and policy engines |
| Status and counts | The in-memory cache, or the native state when the cache is cold |

A frame that fails to decode is reported as an error, never as an empty success, so a script
can tell "nothing matched" apart from "the answer never arrived".

## Shutdown and failure behaviour

- **Signals.** On SIGINT or SIGTERM the daemon stops accepting connections, cancels background
  work, and gives owned tasks up to 30 seconds to finish. It then removes the socket file.
- **Interrupted refresh.** A failed refresh leaves the previous snapshot in place and the next
  pass retries. A missing or stale snapshot only changes which path a caller takes.
- **No network.** Daemon-served queries then answer from the in-memory index and the native
  databases. On Arch the AUR lane is bounded by its timeout, and the rules in
  [package search](./package-search.md) decide whether a failed lane is reported or skipped.

**Limit:** a graceful shutdown is best effort. Killing the process outright causes no
corruption — the state is derived — but the previous snapshot stays on disk, so counters may
read older values until the next refresh.

## Running it as a service

To have the daemon available after login, run it under your session's service manager so it
is restarted for you and its output is captured where you can read it. Configuration details,
including the pairing requirement between `omg` and `omgd`, are in
[configuration](./configuration.md) and [installation](./installation.md).

**Limit:** only run a daemon your release contains, and restart it after an upgrade so the
running process matches the build you installed. Do not start a second instance to make a
status message go away: check `omg daemon-status` first.

## Where to go next

- [IPC](./ipc.md) for the wire format, socket resolution, and request families.
- [Cache](./cache.md) for the three tiers and their freshness rules.
- [Troubleshooting](./troubleshooting.md) when the daemon or its socket misbehaves.
- [Under the hood](./under-the-hood.md) for how the pieces fit together.

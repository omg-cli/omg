---
title: IPC Protocol
sidebar_position: 34
description: Binary protocol for CLI-daemon communication
---

# IPC

**In plain words:** this page describes how the `omg` command talks to the `omgd`
background helper: where the connection lives, how one message is framed, what can be
asked for, and what happens when the two disagree.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

`omg` and `omgd` are separate programs. They talk over a Unix domain socket on the local
machine, so a request never leaves the computer and no port is opened.

## Where the socket lives

The path is resolved in this order, taking the first that applies:

```bash
# 1. an explicit override, if you set one
export OMG_SOCKET_PATH=/run/user/1000/omg.sock

# 2. the session runtime directory (the normal case on a desktop Linux system)
#    $XDG_RUNTIME_DIR/omg.sock

# 3. /run/user/<your-uid>/omg.sock when XDG_RUNTIME_DIR is unset
# 4. /tmp/omg-<your-uid>/omg.sock when that directory does not exist
# 5. a private <data-dir>/run/omg.sock when the /tmp fallback exists but fails validation
```

Steps 4 and 5 exist because `/tmp` is shared: any local user could pre-create a directory
with your uid in its name. If the `/tmp` fallback exists but is not a real directory owned
by you with no group or world bits, OMG diverts to a directory only your account can
create. The choice is deterministic, so the daemon and the CLI agree without negotiating.

```bash
# Show the resolved socket, its owner, and whether a process answers there.
omg daemon-status

# Inspect the file and its parent yourself.
ls -ld "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
ls -l "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/omg.sock"
```

The socket is bound with mode `0600` (your read/write only) and its parent directory with
`0700`. Both ends validate the parent before use: a symlink, another user's directory, or a
path with group/world bits is refused rather than silently replaced. That is also why an
unset `XDG_RUNTIME_DIR` never degrades into an operation on `/omg.sock`.

## How one message is framed

```text
frame := [ length ][ version prefix ][ bitcode payload ]
             │            │                  └─ compact binary encoding of one message
             │            └─ protocol version; a peer that does not know it refuses the frame
             └─ delimiter, so both sides can read one message without guessing at the end
```

A framing failure is reported as an error, never as an empty success. This matters when you
script: "no results" and "the answer never arrived" stay distinguishable, so a broken daemon
cannot look like a successful search with zero matches.

## What can be asked for

The request enum in `src/daemon/protocol.rs` is the authority for the current surface:

| Request | Purpose |
| :--- | :--- |
| `Search`, `Suggest` | Package search and completion candidates |
| `Info` | Details for one package |
| `Status`, `Health`, `Metrics` | System status, health probe, and metrics |
| `Explicit`, `ExplicitCount` | Explicitly installed packages and their count |
| `ListUpdates` | Packages with a newer version available |
| `SecurityAudit` | Vulnerability and policy scan work |
| `CacheStats`, `CacheClear` | Inspect or clear the daemon's in-memory cache |
| `RefreshIndex` | Rebuild the in-memory package index |
| `DebianSearch` | Search path for APT-backed builds |

Responses are a `Success` or `Error` envelope carrying a typed result, so a caller can
distinguish an empty result from a failure without parsing text.

## When the daemon is not running

Capabilities differ, and OMG does not pretend otherwise:

| Situation | Behaviour |
| :--- | :--- |
| Core package queries and mutations | Use the direct backend path; the daemon is an optimisation, not a dependency |
| `omg audit scan`, Unix SOC 2 export, `omg metrics` | Require a running daemon and fail explicitly without one |
| Prompt counters (`omg ec`, `tc`, `oc`, `uc`) | Read the status snapshot file directly, so they work with no daemon at all |

See [cache](./cache.md) for the snapshot rules and [daemon](./daemon.md) for lifecycle
detail.

## Limits

- **Local only.** The socket is not a network API: there is no listening TCP port, no
  transport encryption, and no authentication beyond filesystem ownership. Anything that
  can act as your user on this machine can talk to it.
- **Version-bounded.** A frame from a different protocol version is rejected with both
  versions reported (`VersionMismatch`). Keep `omg` and `omgd` from the same release, which
  is why they ship as a pair; see [installation](./installation.md).
- **Derived state only.** Everything the daemon caches can be rebuilt from the native
  package databases, so stopping or killing it never corrupts a package transaction.

The protocol is an implementation detail and may change between releases. Script against
the CLI, not against the socket.

## Where to go next

- [Under the hood](./under-the-hood.md) for the cache tiers and freshness rules behind these responses.
- [Daemon](./daemon.md) for startup, singleton enforcement, and shutdown behaviour.
- [Architecture](./architecture.md) for the component view.

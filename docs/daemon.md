---
title: Daemon Internals
sidebar_position: 31
description: Background service lifecycle, IPC, and state management
---

# Daemon Internals (omgd)

**In plain words:** The daemon is a small helper program that stays in the background so that repeat commands answer faster. It is optional: OMG works without it.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

The OMG daemon keeps package indexes in memory. Most package queries have direct fallback paths; latency depends on the backend, query, cache state, and enabled sources. Vulnerability scans, Unix SOC 2 export, and metrics require a running daemon. Other audit commands have separate backend requirements. See [security coverage](./security.md).

## Daemon Lifecycle

### 1. Initialization and Socket Setup

When the daemon starts, it resolves its operating environment and establishes a secure communication channel:

- **Socket Resolution**: It identifies the optimal path for the Unix socket in this order: `$OMG_SOCKET_PATH` override, `$XDG_RUNTIME_DIR/omg.sock`, `/run/user/<uid>/omg.sock`, `/tmp/omg-<uid>/omg.sock`, and finally a user-private `<data-dir>/run/omg.sock` used only when the `/tmp` fallback exists but fails validation (e.g. pre-created by another local user).
- **Cleanup and Bind**: It ensures a fresh start by removing any stale socket files and binding with strict `0600` permissions (user read/write only). The parent directory is created mode `0700` and is enforced on bind and connect to be a real non-symlink directory owned by the current uid with no group/world bits.
- **Detached launch**: `omg daemon` discards stdout and stderr. Run `omg daemon --foreground`, `omgd` directly, or a service manager configured to capture output when you need logs. Both launch modes require a matching `omgd` executable. Current Linux and macOS release archives include that pair. Archives from v0.1.222 and earlier omit `omgd` on non-Arch targets. For daemon status, use `omg daemon-status`. `omg audit scan`, compliance export, and `omg metrics` require a running daemon.

### 2. State Management

The daemon maintains a comprehensive, thread-safe view of the system's package and runtime environment:

- **In-Memory Cache (moka)**: A high-speed cache for recent search queries, package metadata, and system status results.
- **Persistent Status Snapshot**: Versioned JSON published with a same-directory temporary file, `fsync`, and atomic rename. Audit logs remain a separate hash-chained owner-only file.
- **Package Index**: A searchable index built from official repository databases. Lookup time depends on the query and index state.
- **Runtime Registry**: A dynamic list of all installed language runtimes and their active versions.

### 3. Background Synchronization

A dedicated worker thread handles ongoing system maintenance without interrupting user operations:

- **Periodic Refresh**: Every 5 minutes, the daemon performs a background "vital signs" check.
- **Vulnerability Scanning**: Analysis of installed packages runs as part of the periodic status refresh.
- **Prompt Status**: Updates the binary status file read by prompt counters (`omg ec|tc|oc|uc`). Its contents can lag system changes between refreshes.

---

## Request Processing

Every request from the CLI or third-party tools is processed through a structured execution pipeline:

### Concurrent Handling

The daemon uses an asynchronous, task-based architecture. Every incoming connection is assigned its own isolated task, ensuring that a long-running search or complex dependency resolution doesn't block other users or system queries.

### Request Routing

Requests are automatically routed to specialized handlers based on their type:

- **Package Operations**: Handled by the official repository or AUR backends.
- **Security Audits**: Processed by the vulnerability and policy engines.
- **System Status**: Reading from either the in-memory cache or the persistent database.

---

## Reliability and Failure Recovery

Recovery mechanisms include:

- **Graceful Shutdown**: Upon receiving a termination signal (SIGINT/SIGTERM), the daemon signals all background tasks to complete their current work, saves its persistent state, and cleanly removes the socket file.
- **Self-Healing Index**: If the package index becomes corrupted or outdated, the daemon automatically rebuilds it from the underlying system databases.
- **Network Resilience**: If the internet connection is lost, the daemon falls back to local-only mode, serving results from its cache and system databases.

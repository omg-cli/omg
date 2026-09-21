---
title: IPC Protocol
sidebar_position: 34
description: Binary protocol for CLI-daemon communication
---

# IPC

**In plain words:** This page describes how the OMG command and the background helper exchange messages. It is background reading for people who want that detail.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

`omg` talks to `omgd` over a Unix domain socket on the local machine. Socket permissions are owner-only. Latency depends on the request, the cache, and the backend.

## Framing

Each connection uses length-delimited frames. A frame carries a version prefix and a bitcode payload. Peers reject frames whose version they do not understand. Payload size depends on the message.

The typed request and response enums cover search, package info, system status, security audit, explicit package listings, and cache or health checks. See `src/daemon/protocol.rs` for the current variants.

## Request path

1. The CLI encodes a request and writes one frame.
2. The daemon decodes it, routes it to a handler, and may answer from memory.
3. The daemon writes one response frame.
4. A decode or protocol error fails the call. The CLI does not treat a malformed frame as an empty success.

Without a running daemon, supported package queries use the direct backend path. See [architecture](./architecture.md) and [cache](./cache.md).

## Access

- The socket stays on the local machine.
- The parent directory and socket are checked for owner, type, and permissions before use.
- A path that fails those checks is not used as a fallback onto another user's socket.

---
title: Caching and indexing
sidebar_position: 32
description: In-memory and persistent caching strategies
---

# Caching and indexing

**In plain words:** OMG keeps short-lived copies of information it has already looked
up, so repeating a command is faster. This page explains what is stored, where it is
stored, and how long it stays.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG uses an in-memory cache, a persistent status snapshot, and a binary snapshot for prompt counters. These stores serve different requests. They are not one fallback chain for every command.

## In-memory cache

`omgd` keeps recent search results, package details, and system status in a concurrent memory cache. Eviction keeps that cache bounded. A hit avoids repeating work that is already in memory. Measure the full command before treating a hit as the cost of the operation.

## JSON status snapshot

The daemon publishes `status-cache.json` through a same-directory temporary file, `fsync`, and atomic rename. The file mode is owner-only. The usual location is `~/.local/share/omg/`. `OMG_DAEMON_DATA_DIR` overrides it.

Transaction history and the hash-chained audit log are separate files. Search indexes are rebuilt from native package databases.

## Binary status snapshot

The daemon writes `omg.status` beside its socket. The file is 32 bytes: a magic number, a version, four package counts, and a timestamp. `omg ec`, `omg tc`, `omg oc`, and `omg uc` read it directly when the file is present, owned by the user, and no older than five minutes. A snapshot can lag package changes between refreshes. A prompt counter is not a live transaction record.

## How queries use the caches

Official package queries can use daemon caches or a direct backend path. On Arch, official and AUR searches run concurrently unless `--no-aur` is set. AUR lookup does not wait for a short official result list. See [package search](./package-search.md).

System status is refreshed in the background every five minutes and stored in the in-memory cache and in `status-cache.json`. The same refresh writes `omg.status`.

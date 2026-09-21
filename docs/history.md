---
title: History and Rollback
sidebar_position: 42
description: Inspect recorded transactions and understand recovery limits
---

# History & Rollback

**In plain words:** OMG can record what it changed on your computer. This page explains what the record contains, how to read it, and why a rollback is not the same as restoring a backup.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

History records supported OMG operations. It is not a complete audit of all native package-manager activity, a filesystem backup, or proof of who performed an operation.

## View records

```bash
omg history
omg history --limit 5
omg history --search firefox
omg history --help
```

The usual path is `~/.local/share/omg/history.json`, resolved from the configured data location. Recording can be disabled or directed elsewhere by the caller. Missing records do not prove that no package change occurred. Preserve failure status when interpreting records; a failed action is not a committed installation.

`src/core/history.rs` limits the live history to 1,000 transactions and archives retired records. Back up the associated archive as well as the live file using the paths resolved by the implementation. Stop writers before an approved backup and keep it private. Do not assume copying only `history.json` preserves every record.

## Recording failures

Package execution and persistence are different operations. A package transaction can succeed while history persistence fails; an error must not be read as proof that the package manager changed nothing. Inspect native package state before retrying.

Fedora records match DNF transactions through a unique comment and retain native versions. This does not backfill earlier native history, establish a human actor, or guarantee recovery from a partial RPM failure. See [Fedora implementation notes](../FEDORA-ENGINE.md).

## Rollback

```bash
omg rollback --help
```

Review the transaction and backend requirements before running `omg rollback TRANSACTION_ID`. Rollback changes package state. It depends on retained old versions, current dependencies, and supported backend operations; it is not a guaranteed inverse of install, remove, or update. AUR rebuilds and arbitrary native package operations are not covered by a universal rollback promise.

Retain native recovery tools and a tested machine/VM backup for major upgrades. A package downgrade does not restore application data, configuration migrations, running processes, or external services. Do not automatically confirm rollback in a diagnostic script.

## Corruption and recovery

Preserve malformed history and the exact error. Read-only diagnostics must not rewrite or quarantine evidence. Normal transaction-recording recovery is a separate path and may preserve a corrupt file before recording new data; it does not authorize manually replacing history with an empty array.

Do not edit audit hashes, reset audit logs, or remove archived history to make checks pass. Local audit-chain verification checks consistency, not authenticity or completeness. See [security](./security.md) and [troubleshooting](./troubleshooting.md).

## Before an upgrade

1. Inspect current package state and recent records.
2. Verify recoverable backups and retained package artifacts.
3. Review the update preview and backend-specific warnings.
4. Perform the approved transaction separately from diagnostics.
5. Check native package state and history afterward, including persistence errors.

See [packages](./packages.md), [configuration](./configuration.md), and [CLI reference](./cli.md).

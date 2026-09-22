---
title: History and rollback
sidebar_position: 42
description: Inspect recorded transactions and understand recovery limits
---

# History and rollback

**In plain words:** OMG can record what it changed on your computer. This page explains what
the record contains, how to read it, and why a rollback is not the same as restoring a backup.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

History records supported OMG operations. It is not a complete audit of all native
package-manager activity, a filesystem backup, or proof of who performed an operation.

## What one record contains

`history.json` holds completed transactions. Each entry says what changed, when, and whether
it succeeded:

```json
{
  "id": "0a1b2c3d…",
  "timestamp": "2025-11-11T19:46:40Z",
  "transaction_type": "Update",
  "success": true,
  "changes": [
    { "name": "ripgrep", "old_version": "14.1.0", "new_version": "14.1.1", "source": "extra" }
  ]
}
```

- `transaction_type` is one of `install`, `remove`, `update`, or `sync`.
- `old_version` and `new_version` are optional: an install has no previous version, and a
  removal has no new one. The pair is what makes a rollback possible.
- `source` is the repository a package came from. Sources that need their own install path
  (`aur`, `local`) are treated differently from official repositories, because the system
  package manager cannot restore them on its own.
- `success: false` records an attempt that failed. A failed action is **not** a committed
  installation; check native package state before retrying.

## Read and filter the record

```bash
omg history                        # most recent transactions first
omg history --limit 5              # just the last five
omg history --type update          # install | remove | update | sync
omg history --search ripgrep       # transactions that touched one package
omg history --from 2026-09-01 --to 2026-09-21
omg history --help                 # the exact flags for your build
```

The usual path is `~/.local/share/omg/history.json`, resolved from the configured data
location. Recording can be disabled or redirected by the caller, so a missing record does not
prove that no package change occurred.

## How the file is maintained

- **Bounded live file.** The live file is capped at 1,000 entries
  (`MAX_HISTORY_TRANSACTIONS`). Retired entries move to a sibling JSONL archive rather than
  being dropped, so older transactions remain readable.
- **Atomic writes.** The live file is replaced through a temporary file and a rename, so a
  reader never sees a half-written file.
- **Cross-process locking.** A sibling lock coordinates readers and writers, so two OMG
  processes cannot interleave a rewrite.

```bash
# Back up the live log and its archive together, or only recent history survives.
ls -l ~/.local/share/omg/history.json ~/.local/share/omg/history.json.archive.jsonl
```

**Limit:** copying only `history.json` does not preserve every record. Stop writers before an
approved backup, keep the copy private — it lists installed software — and treat the archive
as part of the same record.


## Recording failures are separate from package failures

Execution and persistence are different operations. A package transaction can succeed while
history persistence fails; that error must not be read as proof that nothing changed. Inspect
native package state, then decide whether to re-record.

Fedora records match DNF transactions through a unique comment and retain native versions.
This does not backfill earlier native history, establish a human actor, or guarantee recovery
from a partial RPM failure. See [Fedora implementation notes](../FEDORA-ENGINE.md).

## Rollback

```bash
omg history                     # find the transaction id you want to return to
omg rollback 0a1b2c3d           # asks for confirmation
omg rollback 0a1b2c3d --yes     # non-interactive; do not add this to a diagnostic script
```

Rollback reinstalls the earlier recorded versions. It works only when all of these hold:

1. The backend supports that operation for those packages.
2. The earlier versions are still available — from the package cache or the repository.
3. The current dependency set still accepts them.

**Limit:** rollback is not a guaranteed inverse of install, remove, or update. AUR rebuilds
and arbitrary native package operations are not covered by a universal rollback promise, and
`omg clean --all` can remove exactly the cached artifacts a rollback would need. On Arch,
`omg clean --cache` checks the last 30 days of history and warns about referenced older
versions. It does not keep those versions on your behalf.

```bash
omg clean --cache --dry-run     # review what cleanup would remove before running it
```

Before a major upgrade, in order:

1. Inspect current package state and recent records.
2. Verify recoverable backups and retained package artifacts.
3. Review the update preview and any backend-specific warnings.
4. Perform the approved transaction separately from diagnostics.
5. Check native package state and history afterwards, including persistence errors.

**Limit:** a package downgrade does not restore application data, configuration migrations,
running processes, or external services. Keep native recovery tools and a tested machine or VM
backup for anything that matters.

## Corruption and recovery

Preserve malformed history and the exact error. Read-only diagnostics must not rewrite or
quarantine evidence. Normal recovery after a corrupt file may preserve a copy before recording
new data, but that path never authorizes replacing history with an empty array, and missing
history does not prove that no transaction occurred.

Do not edit audit hashes, reset audit logs, or delete archived history to make a check pass:
local chain verification checks consistency, not authenticity or completeness. See
[security](./security.md) and [troubleshooting](./troubleshooting.md).

## Where to go next

- [Under the hood](./under-the-hood.md) for this schema alongside caches and the audit chain.
- [Package management](./packages.md) for the operations that get recorded.
- [Configuration](./configuration.md) for where data paths are resolved from.
- [CLI reference](./cli.md) for every `omg history` and `omg rollback` option.

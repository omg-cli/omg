---
title: Troubleshooting
sidebar_position: 50
description: Diagnose failures without discarding configuration or evidence
---

# Troubleshooting

OMG is approaching beta. Diagnose the failing operation before changing package state, configuration, or persisted data. Keep your native package manager available.

## Collect a baseline

```bash
omg --version
omg doctor
omg status
omg daemon-status
```

Record the backend, operating system, exact command, exit status, and whether the failure occurs with the matching daemon running. Redact tokens, usernames, private repository paths, and account information before sharing logs. Do not rerun an installation or upgrade merely to capture output: it can change the machine again.

## Daemon or socket failures

Only use the daemon on platforms whose release includes it; non-Arch release archives do not include `omgd`. See [installation](./installation.md) and [daemon socket resolution](./daemon.md).

If no daemon is running, start the matching executable in a separate terminal:

```bash
omg daemon --foreground
```

Do not start a second instance when your service manager already owns one. Inspect that service's status and logs instead. For a configured `omgd` user service:

```bash
systemctl --user status omgd
journalctl --user -u omgd -n 50
```

A socket error is not permission to remove every candidate socket. Establish the resolved path, owning user, parent-directory permissions, and whether a process still listens there. An unset `XDG_RUNTIME_DIR` must not turn a command into an operation on `/omg.sock`. Do not run OMG as root to work around a user-socket failure or change ownership of another user's socket. If ownership cannot be established, stop and report the error.

## Cache errors

The daemon snapshot is `status-cache.json`, not the obsolete `cache.redb`. Use [cache documentation](./cache.md) to identify the actual cache and its owner. Stop the owning daemon before an approved recovery operation; preserve the failing file for diagnosis. Do not delete the entire OMG data directory: it also contains runtime installations and persisted user records.

A missing search result can also mean unavailable repositories, disabled sources, stale native metadata, or an unsupported backend. Compare the same query with the native package manager. `omg sync` changes repository metadata; it is not a read-only diagnostic.

## Shell hooks and completions

Inspect your shell configuration before adding another hook. Use the instructions for your actual shell in [shell integration](./shell-integration.md), then open a new shell. Multiple version-manager hooks can compete for PATH ordering.

```bash
omg which node
omg list node
command -v node
```

Compare the selected version and executable path. A version file does not install a missing runtime through a directory change. An explicit `omg use` can install software; review the requested version first.

For Zsh, ensure the generated completion directory is on `fpath` before `compinit`. Generate completions using `omg completions zsh`; do not erase shell caches or append duplicate startup lines as a default repair.

## Downloads and package failures

Check free space, provider availability, and the exact download error. Proxy URLs may contain credentials: do not print proxy environment variables into public logs. Do not disable checksums, signatures, provenance, or policy to make a failing download succeed.

AUR builds execute community build recipes. Inspect the recipe, dependencies, and retained build log before retrying. Clearing the AUR cache loses useful evidence and may require downloading and rebuilding everything. Native APT, DNF, and Homebrew transaction paths have different policy coverage from Arch; see [security](./security.md).

For a policy rejection:

```bash
omg audit policy
omg info PACKAGE
```

Obtain the policy owner's approval before changing a requirement. A dry-run is a preview, not proof that a subsequent transaction is safe or will succeed.

## History, audit, and rollback failures

Never replace malformed history with `[]`, reset audit logs, or edit hashes to make verification pass. Preserve the original bytes, backups, permissions, and error output. Stop writers before making a private backup for investigation. Missing history does not prove that no transaction occurred.

```bash
omg history
omg audit verify
```

Audit-chain consistency is not authenticity or completeness. History and audit files can contain sensitive inventory information; do not publish them without review.

Rollback depends on the backend, retained package versions, and current dependencies. It is not a filesystem snapshot or a guaranteed inverse of installation. Do not downgrade packages or rebuild an old AUR recipe without reviewing the consequences. See [history and rollback](./history.md).

## Terminal dashboard

Check terminal capabilities and locale rather than forcing a misleading `TERM` value. If an exited process left the terminal unusable, `reset` or `stty sane` can restore terminal settings. Report reproducible rendering defects with the terminal name and dimensions; omit private account data from screenshots.

## Build failures

Use the backend-specific source build instructions in [installation](./installation.md). Preserve the first compiler/linker error, compiler version, feature flags, and checkout revision. Do not start with `cargo clean`, change the release profile, or disable verification based on an old troubleshooting recipe. Store build output outside `/tmp`.

## No blanket reset

There is no safe universal “reset everything” command. Configuration, history, audit chains, installed runtimes, and package databases have different owners and recovery requirements. Keep the failure evidence and choose a bounded repair with a rollback plan.

See also: [FAQ](./faq.md), [configuration](./configuration.md), and [quickstart](./quickstart.md).

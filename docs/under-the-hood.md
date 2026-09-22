---
title: Under the hood
sidebar_position: 35
description: How the CLI, daemon, caches, AUR pipeline, history, and audit chain actually work
---

# Under the hood

**In plain words:** this page explains what really happens when you run a command, which
files are involved, and where each mechanism stops. Read it when you want to reason about
a failure instead of guessing at one.

> New to the terminal? Read [Getting started](./getting-started.md) first. The
> [glossary](./glossary.md) defines every term used here.

Every section below states the mechanism, then its limit. Nothing here is a promise that
the behaviour is stronger than the code that implements it.

## Two programs, one workflow

Releases ship a CLI (`omg`) and a daemon (`omgd`). They have separate jobs:

| Program | Owns | Without it |
| :--- | :--- | :--- |
| `omg` | Argument parsing, backend queries and mutations, policy, output, prompt counters, interactive views | Nothing works; this is the program you run |
| `omgd` | A warm in-memory index, cached vulnerability results, background status refresh, the JSON and binary status snapshots | Package commands and vulnerability scans still work through direct paths; Unix SOC 2 export and metrics need the daemon |

```bash
omg daemon --foreground    # start omgd in this terminal so you can read its output
omg daemon-status          # resolved socket, ownership, and whether a process answers
```

**Limit:** the daemon keeps derived state only. Killing it cannot corrupt a package
transaction; restart it and the caches refill on demand.

## How the CLI talks to the daemon

The transport is a Unix domain socket, resolved in this order: `OMG_SOCKET_PATH`, then
`$XDG_RUNTIME_DIR/omg.sock`. A missing `XDG_RUNTIME_DIR` never turns the path into
`/omg.sock`; the CLI refuses to guess.

```
frame = [ length ][ version prefix ][ bitcode payload ]
        └ both peers reject a version they do not understand
```

```bash
# The socket and its parent directory are checked for owner, type, and mode first.
# A path that fails those checks is not silently replaced by another user's socket.
ls -l "$XDG_RUNTIME_DIR/omg.sock"
omg daemon-status
```

A decode or protocol error fails the call. The CLI never reports a malformed frame as an
empty success, so "no results" and "the answer never arrived" stay distinguishable.

**Limit:** the socket is local-machine only. It is not a network API and has no transport
encryption or authentication beyond filesystem ownership.

## The three caches, and what a "hit" means

| Store | Location | Lifetime | Read by |
| :--- | :--- | :--- | :--- |
| In-memory cache | `omgd` process | Process lifetime, bounded eviction | Daemon-served queries |
| `status-cache.json` | `~/.local/share/omg/` (or `OMG_DAEMON_DATA_DIR`) | Rewritten by each background refresh | Tools that need structured status |
| `omg.status` | Beside the socket | Rewritten every refresh; read only when ≤ 5 minutes old | `omg ec`, `omg tc`, `omg oc`, `omg uc` |

`status-cache.json` is published atomically: a same-directory temporary file, `fsync`,
then rename, with owner-only permissions. The binary snapshot is a fixed 32 bytes:

```text
offset  size  field
0       4     magic 0x4F4D4753 ("OMGS")
4       4     format version
8       16    four u32 counts: total, explicit, orphan, updates-available
24      8     unix timestamp (seconds)
```

```bash
# Prompt counters read that file instead of starting a daemon or querying a backend.
omg ec      # explicitly installed packages
omg tc      # total installed packages
omg oc      # orphan candidates
omg uc      # available updates
```

**Limit:** a snapshot can lag reality between refreshes, and a rejected file (wrong
owner, wrong size, stale timestamp) silently falls back to the slower path. A prompt
counter is a cache read, not a live transaction record.

## Reaching the package database

| System | Query path | Mutation path |
| :--- | :--- | :--- |
| Arch | `libalpm` through direct FFI, plus the AUR over HTTPS | ALPM transaction, with sudo when the database must change |
| Debian / Ubuntu | Native APT database | Native APT |
| Fedora | RPM database reads | DNF, with a subprocess fallback when the database format needs it |
| macOS | Homebrew data | Homebrew |

OMG binds the Arch library instead of running `pacman` for every query, which is why
search latency does not track the cost of starting a second process. On Arch, official
repositories and the AUR are queried concurrently unless you pass `--no-aur`, and the AUR
lookup has its own timeout.

```bash
omg search ripgrep --no-aur     # skip the network-backed AUR lane entirely
omg search ripgrep --detailed   # add source metadata such as votes and popularity
```

**Limit:** a short result list is not proof that a package does not exist. Repositories
can be unsynced, sources disabled, or the AUR lane timed out. Compare with your native
tool before concluding anything.


## The AUR pipeline, gate by gate

An AUR entry is a recipe that will be executed, and its output archive can carry install
hooks and privileged files. OMG therefore treats both the recipe and the archive as
executable input and runs five gates:

| Gate | What it does | What it blocks |
| :--- | :--- | :--- |
| 1. Fetch | Downloads sources without executing the PKGBUILD | Recipe code running before you have seen it |
| 2. Review and build | Hashes the complete source tree, rechecks it, then builds in Bubblewrap with an isolated home, a cleared environment, and no build network by default | Network access, host environment leakage, writes outside the sandbox |
| 3. Inspect | Parses every output archive without extracting it | Traversal paths, duplicate entries, device/FIFO/socket members, escaping links, inconsistent metadata, undeclared or changed install hooks |
| 4. Rebuild | Rebuilds archives containing install hooks, capabilities, setuid/setgid files, systemd units, kernel modules, package-manager hooks, or `/etc` payloads in a second private invocation with the same `SOURCE_DATE_EPOCH`, and requires byte-identical output | A single build's accidental or deliberate output substitution |
| 5. Hand off | Copies accepted bytes into a sealed `memfd`; the privileged transaction accepts only that handoff and reinspects the staged bytes | Time-of-check/time-of-use swaps between inspection and installation |

```bash
omg install visual-studio-code-bin   # AUR entry; review is on by default
omg install --review some-aur-pkg    # force the review prompt even if configuration relaxed it
omg update --aur-only                # refresh AUR packages; leave official upgrades to pacman -Syu
```

An archive with `.INSTALL`, setuid/setgid files, or file capabilities needs a separate
attended confirmation. `--yes` does not answer that prompt, and unattended runs fail
before that archive reaches the privileged step.

**Limit:** matching hashes prove that two builds produced the same bytes. That is
correlation and tamper evidence, not a publisher signature; a malicious recipe that builds
deterministically still produces malicious output. Publisher verification is the
PKGBUILD's `validpgpkeys` job. See [AUR support](./aur.md) for the full policy.

## Managed developer tools

`omg tool install` applies one policy per ecosystem instead of inheriting whatever the
ecosystem does by default:

| Ecosystem | Default |
| :--- | :--- |
| npm | Stage with lifecycle scripts disabled, run npm signature verification, then activate |
| Python | Dedicated virtual environment, wheels required |
| Cargo | `--locked`, so the dependency graph matches the lockfile |
| Go | CGO off, automatic toolchain download off, checksum and proxy policy set |

```bash
omg tool install prettier    # npm-backed: scripts stay disabled while staging
omg tool install httpie      # Python-backed: isolated virtual environment
omg tool list                # everything OMG manages on this machine
```

**Limit:** these policies apply to OMG's own install path. They do not change a separately
invoked `npm install`, and they do not sandbox a project task you run yourself.


## Environment records and drift

`omg env capture` writes `omg.lock`, which contains:

- the versions of the registered runtimes and tools that the probe finds on this machine;
- the explicitly installed packages reported by the backend;
- a schema version, a timestamp, and a SHA-256 fingerprint computed over the normalized
  runtime and package lists.

```bash
omg env capture                                      # write omg.lock in this directory
omg env check                                        # compare the record with this machine
omg env sync https://gist.github.com/USER/GIST_ID    # adopt a record; back up a differing local file
```

Capture needs a build with the Arch or Debian backend. A Fedora build refuses the
operation explicitly rather than writing a partial record, so `omg env check` cannot
silently succeed on an unsupported backend.

**Limit:** a record is inventory, not a recipe. Neither `check` nor `sync` installs
anything or reproduces an identical machine, and dependency resolution is not replayed.

## History, rollback, and cached artifacts

Every recorded transaction is one entry in `history.json`:

```json
{
  "id": "…",
  "timestamp": "2025-11-11T19:46:40Z",
  "transaction_type": "Update",
  "success": true,
  "changes": [
    { "name": "ripgrep", "old_version": "14.1.0", "new_version": "14.1.1", "source": "extra" }
  ]
}
```

Writes go through a temporary file and a rename under a cross-process lock. The live file
is capped; retired entries move to a sibling `.archive.jsonl` instead of being dropped.

```bash
omg history --limit 5
omg history --type update --search ripgrep --from 2026-09-01
omg rollback 0a1b2c3d             # needs the earlier version still to be available
omg clean --cache --dry-run       # review package archive cleanup
```

On Arch, `omg clean --cache` checks the last 30 days of history and warns when
cleanup may remove older versions used by rollback. The warning does not keep
those archives. Keep a backup of any exact older archive you may need.

**Limit:** rollback reinstalls an earlier recorded version. It needs backend support, the
old package still being available, and a dependency set that still accepts it. It is not a
filesystem snapshot, and `omg clean --all` can remove artifacts a rollback would need.

## The audit chain

Security-relevant events are appended to a JSONL log whose entries carry `prev_hash` and
their own chain hash:

```text
entry N: { …, "prev_hash": hash(entry N-1), "hash": sha256(canonical fields + prev_hash) }
```

Writers read the last hash under a lock, so two concurrent processes cannot fork the
chain. `omg audit verify` recomputes the linkage and reports the first entry that does not
match.

```bash
omg audit verify                          # recompute the chain, report the first break
omg audit log --limit 20 --severity warning
```

**Limit:** the chain proves internal consistency, not authorship or completeness. Anyone
who can rewrite the file can also recompute the chain. Treat it as tamper evidence for
local review, not as an independently anchored record.

## Privilege and handoffs

OMG asks for elevation only when a validated transaction must change the system package
database. It refuses to build AUR packages when started as root, and privileged
subprocesses run from trusted executable paths with dangerous environment settings
scrubbed.

```bash
omg install ripgrep    # your shell stays unprivileged; sudo is requested at the last step
```


## Reading a result correctly

- **Exit status** is the machine-readable outcome. `omg doctor` exits 1 when it finds an
  issue, and a drifted `omg env check` exits non-zero. Branch on the status, not the text.
- **`--json`** is accepted by the parser, but not every command implements a stable
  schema. Check the specific command before parsing its output.
- **Prompt counters** use a cached snapshot when it passes validation, then take a
  fallback path when it does not. Shell hooks can print zero for some counters
  without a valid snapshot. Use `omg status` for a fresh count and the native
  tool when you need the authority.
- **Dry runs** preview a plan. They are not a safety verdict about the resulting package.

## Source map

| Question | File |
| :--- | :--- |
| Which commands and options exist? | `src/cli/args.rs` |
| How is a project task resolved? | `src/core/task_runner.rs` |
| How does the daemon frame messages? | `src/daemon/protocol.rs` (see [IPC](./ipc.md)) |
| How is the prompt snapshot laid out? | `src/core/fast_status.rs` |
| What does a lockfile contain? | `src/core/env/fingerprint.rs` |
| How is history recorded? | `src/core/history.rs` |
| How is the audit chain built? | `src/core/security/audit.rs` |
| Where do paths come from? | `src/core/paths.rs` |

## Where to go next

- [Architecture](./architecture.md) for the component-level view.
- [Security](./security.md) for what audit evidence does and does not prove.
- [Troubleshooting](./troubleshooting.md) for bounded repairs when something fails.
- [Glossary](./glossary.md) for any term used above.

**Limit:** the sandbox covers OMG's build path, not the rest of your machine. Running OMG
itself with `sudo` to work around an error is never the intended fix.

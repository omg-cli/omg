---
title: Performance investigation
sidebar_position: 36
description: Measure OMG honestly and tune the knobs that actually exist
---

# Investigate OMG performance

**In plain words:** a few settings make repeated commands faster, and a few habits make
measurements trustworthy. This page lists the knobs that exist, what each one really changes,
and where the trade-offs are.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

Measure the operation you actually need before changing anything. A warm official-repository
query, an AUR search over the network, and a package installation have different costs, and a
change that helps one can be irrelevant to another.

## What each knob changes

| Setting | What it changes | Trade-off |
| :--- | :--- | :--- |
| `omg daemon` running | Selected queries can reuse a warm index and status cache | A background process holds memory and an open socket; simple search and info paths can still query directly |
| `omg status --fast` | Skips the slower dependency scan and reports counts | Fewer details in the output |
| `omg ec`, `tc`, `oc`, `uc` | Read a valid, fresh 32-byte snapshot when available | Fall back to a daemon request or direct package data if the file is missing or stale |
| `omg search --no-aur` | Removes the network-backed AUR lane from Arch searches | You lose AUR results for that query |
| `omg update --check` | Reports what would change and changes nothing | One extra command before the real update |
| `omg update --fast` | Sync and upgrade in one operation, no preview | You give up the review step |
| `omg update --turbo` | Skips the database sync, uses cached data, parallel extraction | Metadata may be stale; run `omg sync` first if that matters |
| `OMG_AUR_PARALLEL=<1-8>` | AUR build parallelism for one run, overriding the default | More concurrent `makepkg` processes need more memory |
| `[aur] build_concurrency` | The configured AUR build default | 1 is the shipped default; raise it deliberately |
| `[aur] cache_builds`, `enable_ccache`, `enable_sccache` | Reuse built packages and compiler output | Only helps when build inputs are genuinely reusable |

## Where the time actually goes

```bash
# Which path a query takes: daemon-served, or the direct backend path.
omg daemon-status

# The same query with both lanes, then without the network-backed AUR lane.
omg search ripgrep
omg search ripgrep --no-aur
```

On Arch, official repositories and the AUR are queried concurrently and the AUR lane is
bounded by its own timeout, so a slow AUR does not hold official results hostage. See
[package search](./package-search.md) for the exact rules.

```bash
# Isolate the daemon: run it in its own terminal, then repeat the same query.
omg daemon --foreground
```

Separate cold start-up from warm queries, and keep the query, the enabled sources, and the
cache state identical between runs. The cache tiers and their freshness rules are in
[cache](./cache.md).


## AUR build parallelism, with bounds

Builds are process-heavy, so the parallel count is clamped rather than trusted:

```bash
# One run with a specific parallelism; values outside 1-8 are clamped with a warning.
OMG_AUR_PARALLEL=4 omg update --aur-only
```

```toml
# ~/.config/omg/config.toml — set the default once
[aur]
build_concurrency = 4
cache_builds = true
```

Choose the number from both available memory and CPU cores: a single compiler already uses
several cores, and parallel builds add processes on top of that. Reduce it if swapping or
memory pressure appears. Keep sandboxing and review enabled — an unsandboxed native build is
not a performance recommendation, because it runs package code with broader host access.

## Package transactions are serial

```bash
# One transaction for several packages, not several background installs.
omg install gcc clang rustup
```

Independent package-manager processes compete for the same database lock, so running several
`omg install` jobs in the background to "parallelize" system changes makes the work slower and
harder to reason about. AUR build concurrency is a different setting from transaction
concurrency. Use a disposable machine for experiments like the one above.

## Downloads and mirrors

```bash
omg doctor --network    # connectivity, mirror configuration, and tool checks
```

During a sync, mirrors are probed with concurrent `HEAD` requests under a bounded timeout and
the first success wins, rather than trying each mirror in turn. If downloads are slow, check
repository and mirror state before attributing the time to OMG, and never relax signature,
checksum, or provenance checks to improve timing.

## Caches in CI

Cache only what the job needs. Avoid uploading the whole OMG data directory without review: it
can contain audit history, account state, telemetry queues, and environment inventory.
Partition caches by platform, backend, toolchain, and dependency inputs, and never restore an
untrusted cache into a privileged job. Do not benchmark storage by writing to `/tmp`, which
may be memory-backed.

## Limits

- **No universal speedup.** Results depend on the backend, the query, the cache state, the
  repository set, and the storage. Recorded runs are evidence for their recorded conditions;
  see [benchmark methodology](../benchmarks/README.md).
- **`--fast` and `--turbo` trade review for time.** They are deliberate shortcuts, not
  defaults, and `--turbo` can act on metadata a sync would have refreshed.
- **Concurrency is bounded for a reason.** AUR builds are clamped to 1-8; exceeding your memory
  budget causes swapping, which is slower than a lower setting.
- **Compiler caches are conditional.** ccache and sccache help only when build inputs and cache
  configuration allow reuse; no fixed percentage improvement is promised.
- **Smoke-test durations are not latency.** They include setup and assertions.

When you report a regression, include the reproducible command, before-and-after artifact
identifiers, sample counts, raw timings, and the environment differences. See
[contributing](../CONTRIBUTING.md) and [daemon behaviour](./daemon.md).

## Where to go next

- [Under the hood](./under-the-hood.md) for cache freshness, mirror racing, and the AUR gates.
- [Cache](./cache.md) for what is stored and what is safe to remove.
- [Package management](./packages.md) for the update and cleanup commands themselves.

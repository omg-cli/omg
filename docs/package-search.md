---
title: Package search
sidebar_position: 33
description: Official repository queries, AUR enrichment, and result limits
---

# Package search

**In plain words:** This page explains where search results come from, how OMG treats community sources, and why a short list is not the same as an empty one.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

```bash
omg search ripgrep
omg search ripgrep --no-aur
omg search ripgrep --json
```

Search requires a query. On Arch, OMG queries official repositories and AUR concurrently unless `--no-aur` is set. AUR lookup is not conditional on too few official matches. Other platforms use their compiled package backend.

## Official results and AUR

Official queries can use the daemon or a direct backend fallback. On the Arch path, AUR search has a four-second timeout. If AUR lookup fails and official results are available, those results can still be returned. If no official results are available, the AUR failure returns an error rather than an apparently complete empty result.

AUR entries with names already present in official results are removed before presentation. The result list is ranked and limited. A short list is not necessarily the full repository inventory.

## Output

Human-readable output is for inspection. Do not pipe it into an installation command as though every line were a package name. `--json` selects structured search output; consumers must validate the returned fields before taking action.

Bare `omg install` opens the built-in package picker in an interactive terminal. In CI, supply explicit package names.

## Performance

Use the same query, backend, cache state, and sources when comparing results. `--no-aur` excludes network-backed AUR work on Arch. Warm index timings do not establish end-to-end network search performance or equivalent results across tools. See [benchmark methodology](../benchmarks/README.md).

## See also

- [CLI search reference](./cli.md).
- [Daemon](./daemon.md).
- [Caching](./cache.md).

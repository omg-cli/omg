---
title: Package search
sidebar_position: 33
description: Official repository queries, AUR enrichment, and result limits
---

# Package search

**In plain words:** `omg search` asks your package sources for anything matching a word,
shows the most relevant matches, and on Arch also looks in the community AUR collection.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

```bash
omg search ripgrep              # official repositories, plus the AUR on Arch
omg search ripgrep --no-aur     # official repositories only
omg search ripgrep --detailed   # add source metadata such as votes and popularity
omg search ripgrep --limit 50   # raise the result cap (default 15)
```

A query is required; there is no "list everything" mode. Search reads the package databases
your system already has, so the answer is only as current as the last
`omg sync` (or your native tool's equivalent).

## Which sources are queried

| System | Sources | Notes |
| :--- | :--- | :--- |
| Arch | Official repositories and the AUR | Both are queried concurrently unless `--no-aur` is given |
| Debian, Ubuntu | The native APT index | No AUR lane |
| Fedora | The RPM database and DNF metadata | Subprocess fallback when the database format requires it |
| macOS | Homebrew data | No AUR lane |

On the Arch path the AUR lane is bounded by a **four-second timeout**, and the two lanes run
concurrently rather than in sequence. Official results are treated as authoritative:

```text
official lane ─┐
               ├─ joined; AUR latency is capped at 4 s
AUR lane ──────┘
```

- If the AUR lane succeeds, its matches are merged in and entries whose names already appear
  in the official results are dropped.
- If the AUR lane fails or times out and official results exist, search returns the official
  results and logs the AUR failure at debug level. You do not get an error for optional
  enrichment.
- If no official results exist, an AUR failure is surfaced as an error instead of an
  apparently complete empty answer.

## Where the query is answered

```bash
omg search ripgrep          # uses the daemon when it is running, otherwise the direct path
omg status                  # shows whether the daemon is up
```

A running daemon can answer from its in-memory index, which is why the same query can feel
different before and after it warms up. Without a daemon the CLI takes the direct backend
path. Both read the same databases, so results agree; latency and cache behaviour differ.
The daemon's staleness rules are in [cache](./cache.md).

## Reading the output

```bash
omg search ripgrep --json    # structured output for scripts
```

- Human-readable output is for inspection. Do not pipe it into an install command as though
  every line were a package name.
- `--json` is accepted globally, but the structured shape is defined per command: validate
  the fields you depend on rather than assuming a stable schema everywhere.
- Ranking is relevance-based, and the list is capped by `--limit`. A short list is not proof
  that a package is missing.

## Limits

- **Databases, not the internet.** Search shows what your configured repositories currently
  contain. A package added upstream since your last sync will not appear until you refresh.
- **Short lists have several causes.** The query may be specific, the result cap may be low,
  a source may be disabled, or the AUR lane may have timed out. Compare against the native
  tool before concluding anything about availability.
- **Search is not a trust signal.** A result, its vote count, and its popularity describe the
  source metadata, not the safety of the code. AUR entries are community recipes; review
  applies at install time, as described in [AUR support](./aur.md).
- **No interactive mode here.** Bare `omg install` opens the package picker; `omg search`
  never prompts, which is what makes it safe to script.

## Where to go next

- [Package management](./packages.md) to install, update, and remove what you found.
- [CLI reference](./cli.md) for `omg info`, `omg why`, and the rest of the package surface.
- [Caching](./cache.md) for how long a result may be served from memory.
- [Daemon](./daemon.md) when search behaves differently with the helper running.

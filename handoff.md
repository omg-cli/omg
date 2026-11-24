# OMG CLI audit handoff

November 24, 2026

`codex/arch-runtime-audit` starts at `8af84a21e9ebbc4bf2248251913a5aa35f5d13dd`, the `main` commit with the v0.1.226 Lipgloss CLI changes. [PR #1096](https://github.com/omg-cli/omg/pull/1096) · [Base CI](https://github.com/omg-cli/omg/actions/runs/45482788603)

## Runtime inventory

`omg list` and `omg list --json` read installed versions and the active link through the existing filesystem validators, without constructing runtime download managers. An empty named listing gives the canonical command to see available versions. For example, `omg list nodejs` suggests `omg list node --available`.

The runtime integration suite covers the 68-entry inventory, aliases, unreadable directories, incomplete installs, and out-of-tree links. In 31 timed runs on an empty fixture, median debug CLI startup for `omg list --json` fell from 9.45 ms to 4.93 ms. Both builds emitted the same JSON bytes. The timings apply to this WSL fixture.

## Arch and ALPM

- Arch install and dry-run resolve exact names against the configured local install repositories in ALPM order. A missing or invalid install database surfaces an error before AUR fallback. Search-only repositories remain available to package info.
- The terminal `omg info` AUR fallback uses RPC `type=info`. The request accepts a one-character name and checks that the response contains at most one row for that exact name.
- The Arch work shares ALPM handle setup between direct queries and the worker, removes a redundant post-sync daemon refresh, and avoids running a parent spinner over privilege prompts. Four extracted test modules accompany these edits.
- The ALPM fixture verifies that an install-only repository wins over a search-only repository and that a missing install catalog fails. A native Arch fixture exercises install and dry-run with a private daemon socket listening and verifies that the package reaches the local policy check without connecting to that socket. See the [upstream ALPM project](https://github.com/archlinux/alpm) for the Rust parser and repository contracts.
- The Omarchy migration and AUR review fixtures use the exact shell and Python strings from `main`. This preserves the published migration digests and the AUR review test driver's indentation.

## Verification

The batch passed 630 native Arch WSL unit and fixture tests plus 105 unprivileged Ubuntu WSL CLI tests. The native test executable was built in Ubuntu WSL and linked against Arch's system libalpm at execution. Fourteen other ignored tests still require their dedicated fixtures or benchmarks. `cargo fmt --all --check` passed. The staged Rust code passed this Clippy command with warnings treated as errors.

```sh
cargo clippy --locked --no-default-features --features arch,pgp,license \
  --lib --test e2e_runtime_management --test install_update_comprehensive -- -D warnings
```

## Continue on Linux

```sh
git fetch origin codex/arch-runtime-audit
git switch --track origin/codex/arch-runtime-audit
```

The separate advisory service edits are in the Windows checkout. This branch carries the Rust CLI and package manager batch. Local logs and timing samples are under `.git/nov24-cli-audit/`, including `routing-staged-native-receipt.json` and `routing-staged-cli-receipt.json`. The hosted CI and coverage workflows run on pull requests and on `main`.

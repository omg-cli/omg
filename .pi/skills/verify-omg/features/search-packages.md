# Search packages

Users search configured package repositories by name and receive ranked package names, versions, sources, descriptions, and an indication when more matches exist.

## Sub-features

- `search-official`: search only official repositories with a bounded result count.
- `search-detailed`: include detailed source metadata for matching packages.
- `search-aur`: include AUR/community results when network access is available.
- `search-empty`: show the documented no-results behavior for an impossible query.

## How to get to it (user POV)

- Run `omg search <query>` or its alias `omg s <query>` in a terminal.
- Add `--no-aur` for official repositories only.
- Add `--limit <N>` to bound visible results.
- Add `--detailed` for detailed source metadata.

## Driving it with verify-omg

Preconditions: the helper doctor passes and the host pacman database contains official repositories.

- Official bounded search: `./.pi/skills/verify-omg/bin/verify-omg drive search-official -- search zsh --no-aur --limit 3`; require exit zero, the `Search` heading, at least one package containing `zsh`, an `Official` source label, and no more than three displayed package rows before any `(+N more packages...)` summary.
- Detailed search: `./.pi/skills/verify-omg/bin/verify-omg drive search-detailed -- search zsh --no-aur --detailed --limit 3`; require exit zero and additional source/version metadata beyond the compact view.
- AUR-inclusive search: `./.pi/skills/verify-omg/bin/verify-omg drive search-aur -- search visual-studio-code --limit 5`; require exit zero and matching results. Record network/AUR unavailability as a blocked entry point, not an official-search pass.
- Empty search: `./.pi/skills/verify-omg/bin/verify-omg drive search-empty -- search omg-verification-no-such-package-9f67a4 --no-aur --limit 3`; require an explicit no-results state and no fabricated package row.

## Gotchas

- AUR results are network-dependent; use `--no-aur` for deterministic baseline proof.
- The result-count summary is not a displayed package row.
- Repository content changes independently of OMG. Assert query relevance and output shape, not a permanent exact package list.
- Search is read-only, but it may populate only the harness's disposable cache; cleanup removes that cache.

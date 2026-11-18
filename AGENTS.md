# Pi Mono No-Slop Baseline

Use Pi's official model: minimal core, explicit extensions, explicit skills, observable state.

Rules:
- Research before editing on non-trivial tasks.
- Prefer plans before multi-file changes.
- Keep the core minimal; treat extra workflow tools as add-ons, not assumptions.
- Never use `as any`, `@ts-ignore`, empty catch blocks, or delete tests to make failures disappear.
- Verify every non-trivial change with the narrowest real check available, then broaden if needed.
- Prefer review gates for risky work.
- Keep memory and instructions in files you control.

Default stack intent:
- Core: Pi + selected extensions.
- Add-ons: optional review, cleanup, and GitNexus-style safety skills.
- Coordination: external tools only when needed.

## WSL storage discipline

- Before native builds, measure guest usage and free space on the Windows volume backing its VHD. Guest free space alone is insufficient. Budget the run's expected growth plus a host reserve before admitting it.
- Keep build and verification data on C:. Before each native wave, budget projected VHD growth against 100 GB and leave 20 GiB free on the backing Windows volume. Monitor actual growth and stop a build that exceeds its budget.
- Keep a per-distro 100 GB operating budget, with a practical 70 GB used target and an investigation threshold of 80 GB. Existing oversized distros need staged cleanup; do not erase data to satisfy a threshold.
- Give temporary targets an owner, size budget and retirement condition. After each native wave, keep a compact proof receipt and retire confirmed obsolete generated output. Do not duplicate every reproducible executable as a backup.
- Once a PR is merged and its behavior is verified on main, retire its obsolete checkouts, targets, binaries, debug files and fault scratch when no active job needs them. Keep Git source history and compact verification receipts. An old report reference alone does not require permanent artifact retention; record the retired artifact hash and superseding main proof instead of promising replay availability.
- Preserve dirty or unmerged sources, active jobs, essential unresolved-failure evidence, latest useful main verification and the current working QEMU setup. Databases and authored assets are owner data, not obsolete PR output. Verify exact paths, ownership and supersession before deleting; names and age alone do not establish safety.
- Inspect Rust incremental caches for split debug companions still needed by active or unresolved work. Preserve those `.dwo`, `.dwp` and `.debug` files at their referenced paths. Superseded debug files follow the same retirement rule as their old binaries.
- Separate live Linux data from unused VHD allocation. After approved cleanup, trim and compact an idle distro, remeasure host allocation, and restore services deliberately stopped. Do not force global WSL shutdown or unregister distros for routine cleanup.
- Record local incremental/debug profile overrides in run evidence. Do not change coverage or release acceptance settings silently to reduce storage.

## Local development

- Use the existing main checkout for OMG. Create another worktree only when the user explicitly requests one.
- Keep useful source changes in Git and push them before retiring a checkout. Preserve unfinished work in a clearly labeled recovery commit.
- Review and fix tests as development encounters them. Do not restart a repository-wide test audit unless requested.

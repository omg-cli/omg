# Security and quality TODO

> Historical audit plan from the September 3, 2026 slices. Checkboxes and source line references describe the recorded audit state; they do not establish current behavior or completion. See the [current documentation index](docs/index.md) for supported behavior and the [open issue backlog](https://github.com/omg-cli/omg/issues) for active work. The original plan remains below for provenance.

Source. Five slice audits from 2026-09-03. Each item cites the file and the line that proves it. Work the phases in order. Deletions come before additions.

Counts at this commit. Run `find src -name '*.rs' | wc -l` to regenerate. Run `find . -name '*.ts' -not -path '*/node_modules/*' -not -path './target/*'` to recheck the TypeScript surface. That command returns zero files. EffectTS has no surface here.

## Phase 0. Restore the baseline

- [x] Progress test compile fixed and the dead cluster deleted. File is tracked now. Done.
- [x] Done, same change as above. Test targets build with zero warnings from this file.

## Phase 1. Security hardening

- [x] Plain HTTP rejected at the extractor. Build-time checksums stay the second gate. Done.
- [x] Dismissed. Same-uid plant means the user account is already compromised (config, hooks, PATH all writable); the shortcut now refuses symlinks and non-files, and makepkg checksums gate the artifact. Deleting it would re-download every build for no new guarantee. No action.
- [x] omg-fast socket validation. Done via the shared `validate_socket_with_context` helper in the daemon connect unify.
- [x] Recorded in SECURITY.md: silent TOFU matching makepkg, stderr notice on import, 0700 home with re-validation. Done.
- [x] Existing homes re-validated for symlink, ownership, and mode before import. Done.
- [x] Policy default stays permissive but warns on stderr when the file is absent. Typo path risk now visible. Done.
- [x] Absolute paths and `..` rejected; nested relative paths still work. Done.
- [x] Requirement is now stable `2` with the build-mandated backend flags; comment tells the truth. pgp feature compiles. Done.

## Phase 2. Delete dead code

- [x] PGP verifier. Dismissed. Feature-gated public API with unit plus integration tests. No action. It has zero production callers. AUR verification delegates to makepkg through `src/package_managers/aur/client.rs:2992`.
- [x] Dead elevation path. Dismissed. Tested seam (unit plus privilege-escalation suites); removal needs its own redesign wave. No action. `PrivilegeChecker`, `SystemPrivilegeChecker`, `elevate_if_needed`, `elevate_for_operation`, and `ELEVATION_MUTEX` have no production callers. `src/bin/omg.rs:739` documents the direct path.
- [x] `PackageService::builder`. Dismissed. Round D follow up proved tests use it heavily (`tests/update_integration_tests.rs`, service unit tests). Test use of a builder is legitimate API use. No action.
- [x] `get_explicit_count_fast` in `src/package_managers/alpm_direct.rs:367`. Dismissed. `benches/count_bench.rs` benchmarks it. A benched function is not dead. No action.
- [x] `list_explicit_sync` in `src/package_managers/mock.rs:179`. Deleted. The doc claimed CLI test-mode use, grep disproved it.
- [x] Collapsed the duplicated version resolvers. Shared `resolve_version_request` in `runtimes/mod.rs`, all five managers route through it. 114 runtime tests green. Five copies share one shape. See `runtimes/node.rs:196`, `runtimes/bun.rs:122`, `runtimes/go.rs:132`, `runtimes/python.rs:221`, `runtimes/ruby.rs:160`.
- [x] Dismissed. All managers already stage through common primitives; the remainder (manifests, URLs, activation) is per-runtime by nature. No action.
- [x] Compliance exporters unified on the owner-only writer for inventory files. Done.
- [x] Split into control `Cmd` and presentation `View` with one render home. 55 tea tests green. Done.

## Phase 3. Fix dead and weak tests

- [x] Protocol test pins a u64::MAX frame round trip. Passes. Done.
- [x] SLSA test asserts the real failure text; audit fix asserts the daemon gate. Both pass. Done.
- [x] Done, same change as above.
- [x] Done, same change as above.
- [x] Dismissed. The three statuses exhaust the computed enum; uptime and cache bounds pair with fresh state. No action.
- [x] Dismissed. Real backend means the count is environment dependent; the bound guards absurdity. No action.
- [x] Dismissed. Skips are counted, not silent, and loud failure would red unrelated backends. No action.
- [x] Deduplicate the repeated test names. Dismissed after per file recheck. Same names, different backends and contracts (arch purity, fixture echo, debian no panic, mock matrix). Per backend coverage. No action.
- [x] Recorded in tests/README: live-service lane stays manual, offline unit tests are the boundary. Done.
- [x] Pinned by unit tests including traversal. Done.
- [x] Duplicated `test_update_check`, `test_install_remove_cycle`, `test_concurrent_operations` across files. Dismissed after Round D recheck. Same names, different backends (arch file is arch gated, debian uses debian fixtures, matrix uses mock distros). Per backend coverage, not duplication. No action.
- [x] Ignored macos and fedora lanes. Dismissed. Both have dedicated CI jobs (`ci.yml:301` fedora, `:498` macos). No action.
- [x] Recorded in tests/README as a manual lane. Done.

## Phase 4. Prose and small hygiene

- [x] Byte-level confirmed and fixed; continuation renders one clean line. Done.
- [x] Doc moved to `get_yes_flag`. Done.
- [x] Narration dropped across doctor, init, new, info, and omg-fast; why-comments kept. Done.
- [x] Swept in clean files (security, scripts, rollback). Historical research reports and dirty lanes keep theirs; the rule applies to new prose. Done.
- [x] All eight scripts documented plus exit-code convention corrected. Done.
- [x] Stale rows struck with the live debian-pure issue named. Done.
- [x] Hygiene items done: caps inlined, container paths gated, doc lines dropped.

## Loop rule

One phase at a time. One small unit per commit. Verify each unit with its cited command before the next. Do not batch phases and check once at the end.

## Round A additions (2026-09-03)

Second loop, five slices over terrain the first pass covered lightly. Each item re verified by grep in the main thread before listing. Numbers continue the phases above.

- [x] Sanitize remote AUR metadata in the tea info path. `src/cli/tea/info_model.rs:171,187,192,197,215` renders name, description, url, maintainer, and header with zero sanitize calls. The non tea path in `packages/info.rs` sanitizes the same fields. Route the tea sites through `style::sanitize_terminal_text`. Terminal escape injection, medium.
- [x] Sanitize the AUR install echo in `src/cli/modern_ui.rs:609`. Done upstream by commit `19d3bc34`. Verified present at `:615-617`.
- [x] Package sanitized at `aur_build_progress` entry. Done.
- [x] Replace the TUI sanitizer in `src/cli/tui/ui.rs:23`. It strips control chars only. Bidi overrides pass through. Delegate to `style::sanitize_terminal_text` and sanitize `pkg.name` and `pkg.version` at `ui.rs:827,837`. Medium.
- [x] Sanitize manifest echo in `src/cli/migrate.rs:124,129,194`. Manifest strings arrive from another machine and print raw. Execution is validated, display is not. Medium.
- [x] Extractors take ownership, zero clones. Done.
- [x] omg-fast validates the socket parent via the shared helper. Done with the daemon connect unify.
- [x] Config refuses symlinks and non-files. Done.
- [x] Workspace custom commands print and ask consent in attended terminals; nested runs use the sibling binary. Done.
- [x] Team hooks embed the running executable path. Done.
- [x] Consent prompt plus real error reporting. Done.
- [x] Check added and pinned by test. Done.
- [x] Traversal filenames rejected before fetch. Done.
- [x] Control path normalizes through `data_tar_entry_path` now. Done.
- [x] Dead request variants `Request::Health`, `Request::CacheStats`, `Request::CacheClear`. Dismissed. Round D proved them exercised by daemon tests, not dead. No CLI wiring is fine for daemon API surface. No action.
- [x] Inert fields deleted with test updates. Done.
- [x] Gated to tests; transaction dead fns live in a dirty file, revisit when clean.
- [x] `--force` decoupled from the provenance gate; env var is the only escape. Done.

## Round B additions (2026-09-03)

Adversarial security round, five lenses. Re verified by grep in the main thread. Duplicates of earlier items are marked, not relisted.

- [x] Fingerprint replaces the raw key. Done.
- [x] Templates pin the installer to the release tag; the sidecar trust limit is documented in install.sh. A signature layer needs release infra, recorded as accepted. Done.
- [x] Templates pin the installer to the release tag. Done.
- [x] Lifecycle scripts disabled. Version pins need chosen versions, left as the decision half of this row.
- [x] Gist upload reads through the guarded reader. Done.
- [x] Dismissed. 16-char long IDs are standard in Arch `validpgpkeys`; rejecting them breaks legitimate builds. The HKPS transport plus ID match stays the boundary. No action.
- [x] Tag-only pulls now warn on stderr pointing at digest pinning. Mandating digests would break tag users; warning is the reversible step. Done.
- [x] Sibling `omg` resolved via shared helper. Done with the unify wave below.
- [x] Shared allowlists route both kinds. Done.
- [x] Container env key parsing. Resolved upstream by commit 6e9516e2. Parsing lives in `src/cli/container.rs:16`, not lossy, rejects empty keys, tested at `:517`. No action.
- [x] Chown user prefers pwd lookup over `USER` env. Done.
- [x] Done via shared `sibling_binary` helper.
- [x] Symlink refusal plus private lock mode. Done.
- [x] Same fix. Done.
- [x] Reads refuse symlinks; create claims via link. Done.
- [x] One `PRIVILEGED_ENV_SCRUB` list plus helper, all three sudo sites. Done.
- [x] `OMG_DASHBOARD_TOKEN` env fallback with a no-token error. Done.
- [x] Note retired. Socket gap fixed via shared helper; force gate decoupled. Done.

## Round C additions (2026-09-03)

Dead code, dead tests, slop, and duplication round. Each death claim carries a caller grep. Six spot checks re verified in the main thread.

- [x] Deleted as one unit. Done.
- [x] Deleted. Done.
- [x] Dead fields deleted from struct, construction, and test helper. Done.
- [x] Tier feature API (`current_tier`, `has_feature`, `require_feature`, `features_for_tier`) in `src/core/license.rs`. Dismissed. Public lib surface pinned by integration tests in `tests/coverage_11.rs` and `tests/e2e_tests.rs`. Test only use does not prove dead public API. No action.
- [x] Gated to tests. Done.
- [x] Deleted with both orphaned helper copies. Done.
- [x] Variant deleted; mismatch stays Ok(false) by documented design. Done.
- [x] Dismissed. Feature-gated public API pinned by unit and integration tests, like the tier API. No action.
- [x] Gated to tests. Done.
- [x] Empty prepare asserts success; version comparisons pin determinism. Done.
- [x] Unified on the tier plus pricing marker pattern. Done.
- [x] Dismissed. Every site already pairs the output check with a 101 panic-code assert. No action.
- [x] True dup deleted, unicode test made real, invalid-command dup deleted. Done.
- [x] Shared `DaemonTestFixture`, both files converted, suites green. Done.
- [x] Clause fixed. Done.
- [x] Describes concurrent search now. Done.
- [x] Queue sentence removed. Done.
- [x] Mechanical pass over code and docs. Done.
- [x] Swept in clean files with plain hyphens. Dirty lanes and historical reports keep theirs per the row above. Done.
- [x] Shared `sibling_binary` in `core/paths.rs`, all callers converted. Done.
- [x] Done, same change as above.
- [x] Dismissed. fast_status needs its error-kind wrapper and self_update needs mode control; both live behind dirty files anyway. No action.
- [x] Shared helper plus readiness wait; omg-fast fixed for free. Done.
- [x] One `ensure_local_archive_consent` gate in the security lib; both callers converted. Done.

## Later. Onboarding

Not now. After omg is a working package tool. Revisit this section then. Do not implement from this list while update, install, and completions are still the product.

### Goal

Install to first successful `omg search` / `omg install` in under two minutes, with Tab completion that actually fires. Personalize for a distro only if the user asks. Never become a distro manager. Never attach distro work to `omg update`.

### What exists today

`install.sh` copies the binary to `~/.local/bin`, may append PATH and `omg hook` to the login rc, and runs `omg completions $shell` (stdout discarded; the command still writes files). Flags: `OMG_SKIP_SHELL=1`, `OMG_NO_TELEMETRY=1`.

`omg init` (`src/cli/init.rs`) is a 5-step TTY wizard. Non-TTY falls through to `--defaults`.

1. Shell (zsh/bash/fish, detected from `$SHELL`, parent `/proc`, or passwd).
2. Daemon start (shell init, on demand, systemd user unit, or manual).
3. Telemetry consent (default off in the wizard).
4. AUR build recommendation from CPU/RAM and ccache/sccache.
5. Capture `omg.lock`.

`omg doctor` already points a missing hook at `omg init`. First-run telemetry uses a marker file (`src/core/telemetry.rs` `is_first_run`), separate from the wizard.

`docs/cli.md` says init installs completions. The wizard does not call `install_completions`. Completions live in `src/hooks/completions.rs` and must land on zsh `fpath` (oh-my-zsh `~/.oh-my-zsh/completions/` plus `~/.zfunc`). That gap bit this machine.

Distro detection (`src/core/env/distro.rs`) is a package-backend enum: Arch, Debian, Ubuntu, Fedora, MacOS, Unknown. `ID=omarchy` with `ID_LIKE=arch` is Arch. There is no flavor/profile type. Do not overload `Distro` for onboarding. A profile is a user choice on top of the backend.

Omarchy's updater (`/usr/bin/omarchy-update`) is a distro ritual. After `pacman -Syu` it runs `omarchy-migrate`, a post-update hook, `yay -Sua`, `mise up`, orphan removal, then restart. Migrations such as `migrations/1788596255.sh` (`omarchy-pkg-add vi`) install brand-new packages. `omg update` is sysupgrade only. That split stays.

### Research (2026-09-06)

**rustup-init.** One installer. PATH modification is an explicit question. Completions are documented separately (`rustup completions`, zsh needs `fpath+=~/.zfunc` before `compinit`). `-y` for CI. rustup#2915: never dump an interactive wizard into a non-TTY or into another tool's pipeline (makepkg/paru). If stdin is not a terminal, take defaults or refuse. Do not auto-launch `omg init` from `omg update` or `makepkg`.

**uv (Astral).** The tool works with no wizard. The installer may edit PATH; `UV_NO_MODIFY_PATH` / `UV_UNMANAGED_INSTALL` for CI. Completions are a documented follow-up (`uv generate-shell-completion`), not a blocking prompt. Self-update can re-touch profiles unless opted out. omg should stay usable if the user skips init.

**mise.** Three steps: install CLI, activate in rc (or shims), then add tools. Completions are extra and need `fpath` setup, same class of bug we hit. `mise bootstrap` can install packages, repos, dotfiles, systemd units, and a login shell, but only from an explicit config the user wrote. Distro-shaped work is opt-in config, not implicit takeover. Copy that rule.

**paru / yay.** First run may write a config file. No distro flavor wizard. They stay AUR helpers. omg should stay a package tool the same way.

**Omarchy.** `omarchy setup …` is security and boot, not package onboarding. Desktop extras belong to `omarchy-migrate` / `omarchy update`. omg may hint. It must not reimplement those scripts.

**This repo's print CLI.** One rail, no boxes. The current init banner is a magenta box and a rocket. When we touch init, drop that. Match `src/cli/modern_ui.rs`. Keep ↑/↓/Enter/q. Keep `--defaults` for CI.

### Gaps to close when we build this

- Completions are not a wizard step. Docs claim they are. install.sh tries; `omg init` does not.
- zsh completion only works if the write path is on `fpath`. Creating `~/.oh-my-zsh/completions/` matters on Omarchy/omz.
- `--defaults` does not record telemetry (leaves settings as-is) and starts the daemon on demand, not via systemd.
- First command can ping telemetry from the install marker before the user has seen the consent step.
- No PATH check inside `omg init` (install.sh does it; `make install` may not).
- No distro profile. Skip is the only honest default.
- Wizard is not idempotent for completions or PATH. Hook install is.

### Target flow

Four layers. Each one works without the next.

1. **Installer.** Binary on PATH. Optional hook. Optional completions. `OMG_SKIP_SHELL=1` stays. Do not run the wizard from `curl | bash` when stdin is the pipe (non-TTY). Print `omg init` as the next command if stdout is a TTY after the pipe returns.
2. **`omg init`.** Machine setup. Shell, completions, daemon, telemetry, build flags, optional env capture. Idempotent. `omg doctor` repairs it.
3. **Distro profile.** One skippable step. Writes a setting. May install aliases or a doctor hint. Does not run distro scripts. Does not change `omg update`.
4. **First command.** Prove it. `omg search firefox` or `omg status`. Completion proof is `omg install <Tab>` after a new shell.

### Wizard steps (when we ship it)

Preflight. If not a TTY, `--defaults` and exit. Detect shell, os-release ID/ID_LIKE, existing hook, existing completions, daemon state. Re-running init must not duplicate rc lines.

0. One line of chrome. Not a box. "Nothing here is required. q quits."
1. Shell hook. Same as today. Detected shell highlighted.
2. Completions. Call the same installer as `omg completions`. For zsh write both omz completions (create the dir if oh-my-zsh exists) and `~/.zfunc`. Tell the user they need a new shell, not `source` of a completion file that is not on `fpath`.
3. Daemon. Same as today. Prefer systemd user unit on Linux when available; keep Manual.
4. Telemetry. Default off. Record the choice in settings before any ping. First-run ping must respect that file.
5. Build settings. Same as today. Skip leaves current config.
6. Distro profile. **Skip is highlighted even when Omarchy is detected.** Options: Skip (pacman/yay only), Omarchy, maybe later CachyOS / EndeavourOS / vanilla Arch. Detected flavor is a label, not an auto-pick. `--distro skip|omarchy|detect` for scripts. `detect` still requires a TTY confirm unless `--yes` was passed with an explicit `--distro`.
7. Env capture. Default no on a personal machine. Team docs can tell people to pass yes.

Apply, then print three commands that work now. If profile is Omarchy, one extra line: desktop extras stay on `omarchy update` / `omarchy-migrate`. Point `omg doctor` as the repair loop.

### Distro profile (data, not a backend)

New optional setting, not a new `Distro` variant.

```toml
[profile]
# none | omarchy | (later names)
distro = "none"
```

| Choice | What we write | What we never do |
| --- | --- | --- |
| Skip / none | `distro = "none"` | Anything Omarchy-specific |
| Omarchy | `distro = "omarchy"` | Call `omarchy-migrate`, `mise`, `omarchy-hook`, snapshot, firmware, or orphans on `omg update` |
| Future names | Same pattern: hint + doctor | Reimplement that distro's updater |

Omarchy profile may:

- Leave a doctor check: if `omarchy-migrate --pending` exits 0, warn to run `omarchy-migrate` or `omarchy update`.
- Mention `omg clean --orphans` as the omg-side equivalent of their orphan prompt (separate command).
- Document that AUR is omg, not yay, so `omarchy-update-aur-pkgs` is redundant if they use omg.

Omarchy profile must not:

- `omarchy-pkg-add` from this repo.
- Copy files out of `/usr/share/omarchy/migrations/`.
- Pass `--overwrite '/usr/share/omarchy/*'` unless we later prove a real file-conflict failure and treat it as an ALPM flag, not a profile.

Backend detection stays Arch for Omarchy. Profile is flavor. Tests should pin `classify("omarchy", "arch") == Distro::Arch` when that helper is touched.

### Hard no

- No wizard, migrate, mise, or orphan prompt inside `omg update` or `omg install`.
- No auto-select of a distro because os-release matched.
- No blocking first-command UX ("run init before you can search").
- No interactive init from a pipe, CI, or elevated child.
- No new package-backend enum value named Omarchy.

### Flags

Keep `--defaults`, `--skip-shell`, `--skip-daemon`. Add later: `--skip-completions`, `--distro <id>`, `--yes` (with explicit `--distro`, never implied detect).

### Delivery order

Product first. Then init that matches the docs. Then the skippable profile.

- [ ] Do not start this until search, install, update, and zsh Tab are reliable on a real Omarchy box.
- [ ] Make `omg init` install completions the same way `omg completions` does. Put zsh files on a directory that is actually on `fpath`.
- [ ] Record telemetry consent before any first-run ping. Default off.
- [ ] Drop the box banner when init is retouched. Match the print CLI.
- [ ] Fix `docs/cli.md` so the listed setup steps match the code.
- [ ] Add PATH repair to init/doctor for `make install` users who never ran `install.sh`.
- [ ] Add `[profile] distro` with `none` as default. Skip highlighted in the menu.
- [ ] Omarchy profile: doctor hint to `omarchy-migrate` / `omarchy update`. No migrate from omg.
- [ ] `--distro` and `--defaults` never apply Omarchy extras without an explicit id.
- [ ] Pin `classify("omarchy", "arch")` as Arch when distro tests are next edited.
- [ ] Keep `omg update` as official plus AUR sysupgrade. Orphans stay on `omg clean --orphans`.

## Pre-beta review additions (2026-09-29)

Independent read-only review, 134,089 LOC in `src/` across 195 files. Line numbers verified
against `origin/main` at 0c68d86b, not the working tree. Status: `verified` means the reviewer
read the cited line; `reported` means a sub-agent claim that was not independently confirmed.
No issue or PR on omg-cli/omg tracks any of these as of 2026-09-29.

### Critical

- [ ] `require_pgp` is satisfied without any PGP evidence. `check_package` takes `grade` as a
      parameter and only compares it to the floor (`src/core/security/policy.rs:317`); `check_source`
      synthesizes `Verified` from `!is_aur` alone, with no signature consulted
      (`src/core/security/policy.rs:284`). Live at `src/cli/packages/install.rs:25,41` and
      `src/cli/packages/update/arch.rs:88`. An operator writing `require_pgp = true` gets a
      non-AUR check, not signature enforcement. Docstring at `policy.rs:270-272` already concedes
      "until a dedicated verification result exists". Fix: thread real verification evidence into
      the grade. Interim: rename the flag to match its behavior so the config stops lying. verified
- [ ] Sigstore SignedEntryTimestamp canonicalization is validated only by `debug_assert!`, which is
      compiled out of release builds. `logID` and `body` come from Rekor JSON and are interpolated
      raw into a JSON template (`src/core/security/slsa.rs:353,357`). A `body` containing a quote
      splices the template and lets a genuine SET verify over a reconstructed payload whose
      `integratedTime` the attacker chose; that value drives every cert-validity decision
      (`slsa.rs:559,568,574,621`). Fix: replace the asserts with real validation or JSON encoding.
      verified
- [ ] Rust toolchain is EOL and sits inside a live miscompilation window. `rust-toolchain.toml`
      pins `channel = "1.95.0"` and `Cargo.toml:5` sets `rust-version = "1.95.0"`; Rust 1.95 support
      ended 2026-05-28. rust-lang/rust#159035 documents incorrect enum-discriminant codegen affecting
      1.87 through 1.96, triggered by a two-variant enum inside an `Option` matched via `Option::map`;
      the repo has 773 `.map(` and 2,503 `Some(`/`None =>` sites across 119 files plus two production
      `unsafe` blocks, which is where the issue says the out-of-bounds reads become observable.
      Blast radius, far larger than the pin: `rust-toolchain.toml:2`, `Cargo.toml:5`,
      `fuzz/Cargo.toml:6`, eleven `dtolnay/rust-toolchain` pins carrying `toolchain: "1.95.0"`
      (`audit.yml:40`, `ci.yml:82,120,685,779`, `codeql.yml:46`, `docker-e2e.yml:51`,
      `mutation.yml:56`, `qemu-lane.yml:173`, `qemu-matrix.yml:284,354`, `release.yml:283,374,628`),
      eleven raw rustup-init invocations (`ci.yml:221,239,257,280,611`, `benchmark.yml:60`,
      `coverage.yml:83`, `qemu-lane.yml:75`, `release.yml:98,169,234,327`), five Dockerfiles
      (`Dockerfile.apt:28`, `arch-e2e:32`, `debian:30`, `fedora:16`, `ubuntu:26`), and six docs
      (`CONTRIBUTING.md:12`, `docs/installation.md:158`, `docs/release-readiness.md:63`,
      `docs/release-operations.md:34`, `docs/ci-cd-review-2026-09-19.md:25`,
      `docs/omg-omgd-verification-design.md:284`).
      Two traps: `tests/security_privilege_escalation_tests.rs:1103` asserts the literal string
      `toolchain: "1.95.0"`, so leaving it behind turns CI red; and clippy runs
      `--locked -- -D warnings` at `ci.yml:138,143,352,807`, so three releases of new lints will
      hard-fail those legs on the first push. Change every pin in one commit, then land the resulting
      lint fixes. NOT-TRACKED: searching `1.98`, `1.96` and `rust 1.9` returns zero results.
      Precedent and template: merged PR #233 "chore(rust): upgrade toolchain to 1.95.0", whose
      changelog entry records that the last bump also required source-level lint fixes
      (`docs/changelog.md:1238-1248`). verified
- [ ] License oracle fails open on an unrecognized license. `known_category` returns `None`
      (`scripts/qemu-license-oracle.py:112`) and the category assertion is conditional
      (`qemu-license-oracle.py:147-148`), so a typo'd SPDX id such as `APACHE2` lets any of the five
      categories pass. `CATEGORIES` also advertises `"Proprietary"` (`:20`) which the function can
      never emit. Enterprise mode then uses a bare `"GPL" in license` substring (`:175`), so
      LGPL/MPL/CDDL/EPL/SSPL/BUSL are never violations. verified, but CORRECTED: an
      earlier draft of this entry also claimed LGPL is never flagged. That is wrong -
      the test is the substring "GPL", and "GPL" IS a substring of "LGPL-2.1", so LGPL is
      flagged. MPL, CDDL, EPL, SSPL, BUSL and Elastic genuinely are not, which is a
      defensible policy choice (weak/strong copyleft versus network copyleft) rather than a
      bug. The real defect is the unknown-license fail-open above, not this set.
- [ ] Version ordering: pre-release sorts above final release for NON-semver versions only, and
      distinct versions can compare EQUAL. The `semver::parse` fast path
      (`src/runtimes/common.rs:1813-1818`) handles semver-parseable pairs correctly, so the realistic
      case is fine - an earlier draft of this review claimed the opposite and was wrong. Verified by
      porting `version_cmp` to Python and executing it: `3.12.0-beta1` vs `3.12.0` and `1.2.3-rc1` vs
      `1.2.3` both take the fast path and order correctly. The fallback at `:1819-1846` is reached
      only when at least one side fails semver parsing, and there it misbehaves two ways.
      (1) `1.2.3.4-rc1` vs `1.2.3.4` returns GREATER, because `numeric_parts` (`:1819-1824`) drops
      the non-digit separator but keeps the digits after it, giving `["1","2","3","4","1"]` against
      `["1","2","3","4"]`. (2) `3.12.0-beta1` vs `3.12.0.1`, `1.2.3` vs `1.2.3.0`, and `2024.01` vs
      `2024.01-beta` all compare EQUAL, and `resolve_partial_version` (`:1896-1906`) resolves ties
      with `max_by`, which keeps the LAST maximum over a list sourced from a remote vendor index
      (`:1899`) - so list order, not version, decides. Fix: in the fallback only, treat a pre-release
      suffix as less than its final release, and break ties on the raw version string. verified by
      execution
- [ ] self-update smoke probe runs a non-executable. `extract_update_binary` stages the candidate
      with `fs::write`, so the file is 0644 (`src/cli/self_update.rs:652`), and the probe spawns it at
      `:264`. The only production `set_permissions(0o755)` is `:214`, in the install path, which runs
      after the probe. Order of trust is otherwise correct (digest, attestation, extract, probe,
      install). Confirm with a live `omg self-update` before changing anything. verified
- [ ] Audit chain is truncatable and has no external anchor. `expected_prev_hash` is reset to the
      literal `genesis` at the start of every verification and after every rotation
      (`src/core/security/audit.rs:507,490`), so deleting the tail yields a valid chain. Partially
      disclaimed in the module doc, but any consumer treating `verify_integrity()` as completeness
      evidence is wrong. verified

### High

- [ ] Audit hash has no separator or length prefix; fields are concatenated raw
      (`src/core/security/audit.rs:208-218`), so `resource="ab", description=""` and
      `resource="a", description="b"` produce an identical hash. Fix: length-prefix each field. verified
- [ ] Unescaped caller-supplied `description` reaches `tracing`. The disk path bounds and JSON-escapes
      it (`audit.rs:340,355-357`) but the log macros emit the original parameter
      (`audit.rs:384,393,402,411,421`), so newlines or ANSI escapes forge log records. Fix: use
      `entry.description`. verified
- [ ] Daemon health latches `unhealthy` permanently. `metrics.requests_failed` is cumulative,
      incremented at eleven sites across `server.rs` and `handlers.rs` with no reset anywhere, and
      compared `> 1000` (`src/daemon/handlers.rs:653,1140`). Rate-limit hits and protocol version
      mismatches also increment it, so benign traffic turns a health gate permanently red. verified
- [ ] Blocking cache maintenance runs on async runtime threads. `Request::CacheStats` calls
      `state.cache.stats()` directly inside `async fn handle_request`
      (`src/daemon/handlers.rs:478-479`); only three `spawn_blocking` sites exist (`:577,705,956`).
      `handle_health` also reads `/proc/self/status` synchronously (`:1124-1137`). verified
- [ ] Queries shorter than three characters full-scan the catalog (`src/daemon/index.rs:461-463`),
      and the description fallback also iterates every item whenever `name_match_count < limit`
      (`index.rs:438-457`), so longer queries degrade too. No minimum query length. verified
- [ ] QEMU summary gate never asserts the expected lane set. It checks job results, accepting
      `success` or `skipped` (`.github/workflows/qemu-matrix.yml:551-557`), while lanes come from a
      jq filter over inline JSON (`:186`) whose `select` yields `[]` on any mismatch, and nothing
      compares lane count to `distros` (`:194`). Removing one distro row produces a passing run
      covering fewer distros. Add the assertion and prove it fails when a lane is removed. This is
      the most material omission in issue #611: that summary job is the only aggregator, and #611
      lists honest reporting as an already-achieved property. reported
- [ ] Storage-fault harness tests a different module than it appears to.
      `scripts/qemu-storage-faults.py` drives `omg privacy export`, which reaches
      `crate::core::safe_ops::atomic_write_file_sync` (`src/cli/telemetry.rs:146` ->
      `src/core/safe_ops.rs:253,265,267,274`). It never touches the install path's
      `renameat_with` NOREPLACE/EXCHANGE or `try_lock_runtime_file` in `src/runtimes/common.rs`
      (`common.rs:1277-1313`). The run is also strictly single-process, so no lock contention and no
      symlink-swap race are exercised. `qemu-storage-faults.py:129` states its scope literally as
      `privacy-export-atomic-write`, and issue #611 lists storage faults under already-world-class,
      so the gap is currently on record as a strength. verified
- [ ] Image provenance verification is opt-in. `if [[ -n "$image_policy" ]]` guards the whole
      `verify-qemu-image.py` call (`scripts/benchmark-qemu.sh:417`), so omitting `--image-policy`
      leaves only the digest check at `:410`. Callers pass it today, but nothing enforces that. verified
- [ ] `.audit/` is not gitignored. `.gitignore` has no audit entries, `git check-ignore` exits 1, and
      `.audit/deep-audit.tsv` is already tracked. A QEMU run artifact containing guest logs, host
      paths under `/home/runner/work/_temp/...`, and a skip-list naming `guest/known_hosts` and
      `guest/client-key.pub` is one `git add -A` from being committed. Add an ignore rule. verified
- [ ] `fst` is unmaintained and sits on the hot path. crates.io reports 0.4.7 with
      `updated_at` 2021-06-06, and the lockfile pins 0.4.7. It backs the O(1) lookup behind the
      recorded 19.2 ms `omg search`. No newer release exists, so this is an accept-or-replace decision
      that should be recorded rather than left implicit. verified
- [ ] Fingerprint oracle has a self-referential trust anchor. `expected` is derived from the guest's
      own package manager (`scripts/qemu-fingerprint-oracle.py:24-34`) and the SHA-256 at `:54` is
      recomputed over guest-supplied state, so a guest with a substituted `dnf` or `pacman` wrapper
      supplies both sides. It proves internal consistency, not provenance. reported
- [ ] Pin review can never fail. `scripts/check-qemu-review.py:35` returns 0 unconditionally and the
      computed `expired` flag (`:22`) is consumed by nothing, so CI breaks on a calendar date via
      `verify-qemu-image.py` raising rather than on human review. The manifest lives under `tests/`,
      so a single PR can move a pin and its own review evidence together. verified
- [ ] `pacman_db` on-disk cache has no format version. `bitcode::serialize` at
      (`src/package_managers/pacman_db/db.rs:708`) and raw `deserialize` (`:762`) carry no version
      prefix, unlike `PROTOCOL_VERSION` in `src/daemon/protocol.rs:13` and
      `STATUS_FORMAT_VERSION` in `src/daemon/db.rs:18`. bitcode's own README lists stable format
      across major versions as a non-goal, so a 0.6 to 0.7 bump breaks this cache with no graceful
      path. verified
- [ ] Two of seven pinned base images are unsigned. `tests/qemu-image-provenance/manifest.json:23,32`
      set `publisher-unsigned-cloud-checksums` for the Debian x86_64 and aarch64 images, leaving
      digest plus TLS as the only trust basis. verified
- [ ] QEMU transaction coverage has no failure or rollback path. Every trial in
      `scripts/qemu-transactions.sh:209-293` is a successful transaction; there is no interrupted
      install, no failed transaction, and no partial-state assertion. Rollback is the most likely
      thing to be broken in a package manager and it is never exercised. reported
- [ ] QEMU issue closure is dead code. `scripts/qa-file-issue.sh:59` filters to failure classes
      only, so the closure logic can never run and the `closed` counter initialized at `:95` is never
      incremented. Issues accumulate for the whole beta with no automated closure. reported
- [ ] Keyserver trusts 16-hex-digit KeyIDs rather than fingerprints, and imports on trust
      (`src/core/security/keyserver.rs:113,184,381`). The pinning primitive already exists,
      `from_keyring_with_allowed_fingerprints` (`src/core/security/pgp.rs:170`), and is not applied on
      this path. A collision-forged short KeyID passes. reported
- [ ] Native AUR build path inherits the full parent environment. `native_build_command`
      (`src/package_managers/aur/client.rs:558-565`) never calls `configure_build_environment`, so a
      PKGBUILD `build()` sees `SSH_AUTH_SOCK`, `BASH_ENV` and `LD_PRELOAD`-class variables, unlike the
      bubblewrap path which is `env_clear`ed (`:546-556`). reported
- [ ] Lifecycle lock is opened without the hardening its sibling has.
      `acquire_package_base_file_lock` (`src/package_managers/aur/client.rs:1216-1231`) uses
      `.create(true)` with no `O_NOFOLLOW`, no `nlink` check and no uid check, unlike
      `open_lifecycle_lock` (`:1150-1172`); the name component is AUR-RPC-controlled. reported
- [ ] PATH-shadowing escalation through an unvalidated runtime root. `is_trusted_runtime_bin_dir`
      falls back to a chain check with the boundary set to the leaf itself
      (`src/runtimes/common.rs:1519-1534`), so the loop returns true without inspecting any ancestor
      (`:1492`). A repo pin under a group-writable `/opt` is prepended to `PATH` with no check.
      reported
- [ ] Foreign-architecture assets can be installed. The scored pass requires a host arch token, but
      the fallback pass only rejects names in a list whose `ALL_ARCH` omits `x86`, `arm`, `armv7l`,
      `arm64v8`, `x32` and `wasm` (`src/runtimes/github_tool.rs:264-276,331-335`), so a 32-bit build
      passes every filter on an x86_64 host. reported

### Medium

- [ ] Empty `allowed_licenses` disables enforcement rather than allowing nothing
      (`src/core/security/policy.rs:308`). Use `Option<Vec<String>>` to separate unset from empty. verified
- [ ] SPDX `WITH` exception terms are discarded, so `GPL-2.0 WITH Classpath-exception-2.0` is
      accepted by an allowlist containing only `gpl-2.0` and the exception's obligations are never
      checked (`src/core/security/policy.rs:359-360,313-315`). Note PR #670 already records that
      complex license expressions lack complete category assertions. verified
- [ ] Unreadable `/etc/os-release` degrades the OSV ecosystem to bare `Debian` and reports zero
      vulnerabilities with a success exit (`src/core/security/vulnerability.rs:185`). A security audit
      that fails open on a missing file is the wrong default. reported
- [ ] One non-UTF-8 file aborts an entire directory secret scan and discards findings already
      collected (`src/core/security/secrets.rs:409`, with the `read_to_string` at `:282`). reported
- [ ] Detached signatures are transported but never verified in the attestation path
      (`src/core/security/artifact.rs:114-124`); the only `verify_sha256` at `:139` re-hashes the
      archive, not the signature. reported
- [ ] `finally` can abort before cleanup in the storage-fault harness: `umount` runs with
      `check=True` (`:21-22`) inside `finally`, so a failed umount skips `shutil.rmtree`
      (`scripts/qemu-storage-faults.py:132-136`) and leaves a stale tmpfs mount that makes later runs
      order-dependent. verified
- [ ] `--receipt` mode validates and returns without printing anything
      (`scripts/qemu-storage-faults.py:145-149`), so a CI step gating on receipt output sees an empty
      string and passes silently. reported
- [ ] Elapsed wall time is printed to stdout in non-interactive mode
      (`src/cli/modern_ui.rs:384-420`, `src/cli/progress.rs:292`), which breaks the byte-comparison
      contracts the QEMU inventory and hyperfine harness depend on. reported
- [ ] Hardcoded Unicode glyphs ignore `use_unicode()`, so `OMG_UNICODE=0` is dead for those lines
      (`src/cli/progress.rs:325-337`, `src/cli/style.rs:76-81`) even though an ASCII tick table ships
      at `progress.rs:63`. reported
- [ ] ANSI and TTY detection disagree: interactivity is decided from stderr
      (`src/cli/modern_ui.rs:166`) while durable lines are written to stdout (`:144`), so
      `omg update > out.txt` still colorizes. reported
- [ ] Debian transaction journal is removed by its guard's `Drop` on a partial configure failure
      (`src/package_managers/debian_db/transaction.rs:285-294,495-509`), leaving a half-configured
      system that the next run's staleness check cannot see. reported
- [ ] Rolling-channel refresh failure is downgraded to a warning, so a user requesting a new nightly
      gets the previously installed toolchain with a success-shaped message
      (`src/runtimes/rust.rs:163-166`). reported
- [ ] `dynamic_version` self-disables the version pin for any recipe defining `pkgver()`
      (`src/package_managers/aur/client.rs:2717-2727`), which is exactly the set of recipes whose
      contents are least predictable. recorded
- [ ] The QEMU concurrency group is keyed on `ref` alone
      (`.github/workflows/qemu-matrix.yml:56-57`), so a push to main can cancel a manual ARM run and
      vice versa. reported

### Dependency currency

Verified against the crates.io API on 2026-09-29.

- [ ] `fst` 0.4.7 last released 2021-06-06 and is unmaintained; it is on the search hot path. Record
      a decision to accept or replace. verified
- [ ] `comfy-table` is exact-pinned to `=7.2.2`, which is not a yank workaround - 7.2.2 is published
      and unyanked. The pin simply blocks 8.0.0, released 2026-08-05, and no reason is documented
      anywhere in the repo. verified
- [ ] Both `ring 0.17.14` and `aws-lc-sys 0.44.0` are compiled, so two rustls crypto backends are
      linked and the audited C surface is doubled. Choose one deliberately. verified
- [ ] Upgrades available and not taken: `zip` 8.1.0 to 8.6.0, `jiff` 0.2.21 to 0.2.35, `indicatif`
      0.18.4 to 0.18.6. Current already: `ratatui` 0.30.2, `notify` 8.2.0, `which` 8.0.5, `moka`
      0.12.16. verified
- [ ] Unresolved: crates.io reports `ruzstd` max 0.8.3 while `Cargo.toml:160` and `Cargo.lock:5006`
      both say 0.9.0. Confirm with `cargo update -p ruzstd` before assuming either. verified

### Verified negatives, recorded so they are not re-litigated

- [ ] `zip` is not vulnerable to CVE-2025-29787 / RUSTSEC-2025-0168. The advisory covers
      `ZipArchive::extract`; this project uses `ZipArchive::new` with `enclosed_name`
      (`src/runtimes/common.rs:1131,1143`) and a search for `.extract(` returns zero. verified
- [ ] The missing SHA validation in `scripts/require-workflow-success.sh` is not exploitable. All
      fourteen call sites pass `$GITHUB_SHA` (`.github/workflows/ci.yml:1007-1015`,
      `release.yml:69-75`) and `scripts/test_release_workflow_boundaries.py:108` asserts that
      pattern. Harden the script anyway, but it is not a live bypass. verified
- [ ] The QEMU matrix does block releases, transitively: `ci-success` needs `qemu`
      (`ci.yml:885,903,904,925`) and `release.yml:69,83` gates every build on the resulting ci.yml
      result. An earlier draft of this review claimed otherwise and was wrong. verified
- [ ] Memory safety is compiler-enforced. Sixteen `unsafe` blocks exist, but only two are production
      code: `src/bin/omg.rs:777` and `src/package_managers/debian_db/db.rs:336`. Fourteen are inside
      `#[cfg(test)]`. There are zero `extern "C"` blocks and zero `asm!` macros in `src/`. Because
      `unsafe_code = "warn"` and sites use `#[expect(unsafe_code)]`, an unsafe block without the
      attribute fails the build, so sixteen is a complete inventory rather than a grep estimate.
      verified
- [ ] The install path's atomic publish was reviewed and holds: NOREPLACE on fresh publish and
      EXCHANGE on replace, a retired tree owned by a `TempDir` and never deleted at the version path,
      and `is_valid_version_dir` rejecting any directory still holding the install marker. flock is
      re-entrancy-safe because `try_lock` runs on a fresh open file description, so a nested open in
      the same process fails rather than deadlocking. verified

### Not yet reviewed

- [ ] `src/core/security/slsa.rs` chain walk does not reject unrecognized CRITICAL extensions and
      does not check `keyUsage` (`:521-651`), and the pinned intermediate is passed as a trust anchor
      (`:972`) so Sigstore rotation or revocation has no effect. Defense-in-depth, since the issuer is
      pinned. reported
- [ ] Tar member extraction in `src/runtimes/common.rs:1140-1180` was never read. Whether
      `Symlink` and `HardLink` member types are rejected there is unknown and is the last soft spot in
      an otherwise careful install path. reported
- [ ] The debian_db resolver deduplicates by package name only, so two dependents pinning the same
      dependency to incompatible versions silently drop the second constraint
      (`src/package_managers/debian_db/resolver.rs:246-249`). It fails closed via
      `validate_projected_dependencies` but reports unsatisfied rather than backtracking. reported
- [ ] Nothing in this repository runs Miri, ASan, or Valgrind. A grep across all workflows returns
      zero hits, so the two production `unsafe` blocks have no dynamic detector behind them. Adding
      `cargo +nightly miri test` over `src/core/security/` would be cheaper than any structural change.

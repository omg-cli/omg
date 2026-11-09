# omg audit remediation plan

Read-only swarm audit. Source tree NOT modified. Working tree already dirty with prior user work
(52 files, pre-existing, untouched).

HEAD CAVEAT: HEAD moved during the audit, f305afef -> 508bba8d (PRs #776/#778/#780 landed).
Every finding below was re-verified against 508bba8d by the coordinator. Six files that carried
verified findings (error.rs, client.rs, paths.rs, safe_ops.rs, types.rs, protocol.rs, secrets.yml,
validation.rs, usage.rs) are unchanged between the two commits; the drifted files (config.rs,
tool.rs, aur/client.rs, debian_db/db.rs, transaction.rs, install.sh, privilege.rs, completion.rs,
http.rs) were re-checked and all findings still hold - only line numbers moved.

Status: waves 1-6 of 10 complete (59/100 lenses). 324 per-file lenses queued after wave 10.
Tally: 265 findings, 177 proven by running real code (>= 4/5), 10 UNPROVEN (<3, not actionable).
Severity: 0 CRITICAL, 31 HIGH, 81 MEDIUM, 59 LOW, 94 INFO.

Proof discipline (blast-radius): every item cites file:line, names a concrete trigger, rates 1-5.
>=4 means real code ran and failed. Fixes target the root cause and prefer deletion.

## P0 - gates and receipts that cannot fail

### 0.1 Native contract receipts fabricate cleanup=PASS (HIGH, 5/5)
- Where: scripts/run-native-contracts.py:225 - `cleanup='PASS' if result == 'PASS' else 'NOT_STARTED'`.
- Why it is wrong: cleanup status is DERIVED from the test verdict. No cleanup outcome is ever
  measured, so every passing test emits cleanup=PASS regardless of whether cleanup succeeded.
  This is fabricated evidence in a receipt - worse than a missing gate.
- Fix: measure cleanup and report it. If cleanup is genuinely unobservable, emit UNKNOWN rather
  than PASS so downstream gating fails closed.

### 0.2 require_debian_like! records skips as passes (HIGH, 5/5)
- Where: tests/debian_tests.rs:739-747 hand-rolls `eprintln!("Skipping test: ...")` and returns.
  The repo already has the canonical reporter: tests/common/mod.rs:790 `report_skip()` emits
  `[omg-skip] {reason}`.
- Impact: tooling that counts skips by grepping `[omg-skip]` records these as PASSES.
- Fix: delete the macro body and call the existing report_skip. Pure deletion, no new abstraction.

### 0.3 gitleaks does not gate merge; --log-opts does not scope to one commit (HIGH, 5/5)
- Where: .github/workflows/secrets.yml:49 sets `log_opts="$GITHUB_SHA"` - a bare SHA, which gitleaks
  treats as "scan all reachable history". Only :53 narrows it, and only when the base resolves.
  The workflow has no `needs:` dependents.
- Fix: make the range explicit on every event; make ci.yml depend on secrets.yml.

### 0.4 `// gitleaks:allow` in license.rs is on the wrong line (HIGH, 5/5)
- The pragma never applies, so the intended suppression does not happen.

### 0.5 Two test suites are not workspace members and no CI job selects them (HIGH, 5/5)
- 52 passing tests never run.

### 0.6 test_vulnerability_scanner_osv_real can never pass on Arch (HIGH, 5/5)
- The file's target platform yields zero OSV findings, so the non-empty assertion is unsatisfiable;
  and `!vuln.summary.is_empty()` cannot fail.

### 0.7 HTTPS security test audits 6% of src/runtimes/common.rs (HIGH, 4/5)
- Cannot detect a planted plaintext URL.

### 0.8 Hardcoded Cargo feature list in cli_surface.rs has already drifted (HIGH, 4/5)
- Fails the contract-admission gate on the debian-pure CI lane.

### 0.9 Mutation gate is not a coverage bound (MEDIUM, 4/5)
- Unviable mutants are excluded from the denominator, so the 75% score can pass without covering
  the code. Scope is 6 files / ~4.3k lines of ~147k, hardcoded in three places.

## P1 - correctness bugs with proven user impact

### 1.1 Error suggestions die whenever a .context() is attached (HIGH, 5/5)
- src/core/error.rs:11 `err.to_string().to_lowercase()` returns only the OUTERMOST context; users
  see the full `{error:#}` chain at src/bin/omg.rs:873. 798 `.context(` sites affected.
- Fix: `format!("{err:#}")` - one token.

### 1.2 Local daemon timeouts reported as network failures (HIGH, 5/5)
- src/core/error.rs:22 tests "timeout" before the daemon arm at :28.

### 1.3 Daemon connection permanently desyncs after any timeout (HIGH, 5/5)
- src/core/client.rs:196-216 times out only `framed.next()`; the stream stays usable, so the next
  call reads the previous response and :326 hard-fails with a misleading "Request ID mismatch".
- Fix: make the stream unusable on error.

### 1.4 safe_ops create_new branches leak a truncated file and report skip forever (HIGH, 5/5)
- src/core/safe_ops.rs:61-74 and :103-111 write straight to the final path. A failed
  write_all/sync_all leaves a truncated file, and every later call returns Ok(false) forever.
  Reproduced under RLIMIT_FSIZE: a truncated mode-0755 hook that `sh -n` rejects, installed silently
  because src/core/env/team.rs:500 discards the bool - permanently breaking git merge/checkout.
- Root cause: the two branches have OPPOSITE failure semantics. Make both stage-then-persist.

### 1.5 Persistent state dirs accept relative overrides (HIGH, 5/5)
- src/core/paths.rs:156/:245/:293/:328 have no is_absolute() check. State becomes CWD-dependent;
  CLI and daemon can disagree. 60+ call sites.

### 1.6 fast_status_path() can escape the socket's directory (HIGH, 5/5)
- src/core/paths.rs:709 `with_file_name` replaces the last component; OMG_SOCKET_PATH (:537) is
  unvalidated. Also no sun_path length check; validate_socket_ancestor_chain walks `..` verbatim.

### 1.7 PackageSource cannot represent Apt (HIGH, 4/5)
- src/core/types.rs:8-13 has 2 variants; src/daemon/protocol.rs:300-307 folds `Apt | Official =>
  Official`, so Debian packages are reported as Arch "Official".

### 1.8 install_managed blocks the async runtime (HIGH, 5/5)
- src/cli/tool.rs:807 async fn, with sync fs::create_dir_all (:858) and `.status()` (:882-886,
  :900-903) that can run for minutes.
- Fix: tokio::process + tokio::fs, or spawn_blocking.

### 1.9 AUR timeout kills the wrong process group (HIGH, 5/5)
- src/package_managers/aur/client.rs:558-564 launches `setpriv --no-new-privs -- setsid -w makepkg`.
  setsid creates a NEW group, so killpg at :3927/:3936 signals the wrong one and orphans the
  compile tree.
- Fix: kill the setsid'd child's group, or drop setsid and rely on process_group(0).

### 1.10 `-debug` substring filter makes such packages unbuildable (HIGH, 5/5)
- src/package_managers/aur/client.rs:2609 uses `filename.contains("-debug-")`, so a package
  genuinely named `foo-debug` has its own artifact skipped forever. Arch ships such packages.
- Fix: match the parsed package name (already extracted at :2616), not a substring.

### 1.11 Folded Depends: continuation lines are silently dropped (HIGH, 4/5)
- src/package_managers/debian_db/db.rs:2679 and :3033 only match lines starting with "Depends: " /
  "Pre-Depends: ". A folded continuation line starts with whitespace and is dropped, so
  `Depends: libc6,\n libreadline8` loses libreadline8 from dependency resolution.
- Fix: accumulate any line beginning with whitespace into the previous field.

### 1.12 omg config validate always exits 0 (MEDIUM, 4/5)
- src/cli/config.rs:250-256 prints "Found N issue(s)" then returns Ok(()) regardless. Any CI
  gating on it gets a false pass. (The inverse defect exists in `omg doctor`, which prints a
  misleading "Error:" after a clean verdict.)
- Fix: return non-zero when issues > 0, via the existing Result error path.

### 1.13 AUR output closure walks only `depends` (MEDIUM, 5/5)
- Sibling outputs needed by makedepends/checkdepends are dropped from the build plan.

### 1.14 RPC search failures fall back to an index that cannot answer the query (MEDIUM, 4/5)
- Turns a partial API error into a wrong success.

### 1.15 execute_removal holds locks across an abort-prone await (HIGH finding, LOW reachability)
- src/package_managers/debian_db/transaction.rs:1039-1043 holds the process lock, dpkg locks and
  journal across a spawn_blocking await; a cancelled future drops the guards while the task keeps
  mutating dpkg.
- IMPORTANT: :1020 is `cfg!(test)`-gated off in production, so this is not reachable today. The
  right action is deletion when the native APT backend lands, NOT a lock refactor now.

## P2 - data integrity and metrics

### 2.1 Corrupt history archive permanently wedges all future writes (MEDIUM, 4/5)
- src/core/history.rs:386-395; quarantine_corrupt_file exists but is wired only to the live file.

### 2.2 Corrupt usage.json silently kills tracking while `omg stats` hard-errors (MEDIUM, 4/5)
- src/core/usage.rs:454-462 vs commands.rs:1534 - read and write paths disagree on recoverability.

### 2.3 time_saved_ms is 50x inconsistent between install and update (MEDIUM, 4/5)
- src/core/usage.rs:638-642 (flat 1500ms) vs :691-699 (per-package multiply).

### 2.4 History archive has no size cap and is fully re-parsed on every retirement (LOW, 4/5)

### 2.5 queries_today is a mislabeled alias for total_commands (LOW, 4/5)

## P3 - install, performance, polish

### 3.1 install.sh: no umask is ever set (MEDIUM, 4/5)
- All mkdir calls inherit the caller's umask. Set `umask` once near the top.

### 3.2 install.sh: binary picked by `find | head -n1`, not release layout (MEDIUM, 4/5)
- :692-693 - a nested file can shadow the real binary. Select by the documented path.

### 3.3 install.sh: checksum sidecar filename never verified (MEDIUM, 4/5)

### 3.4 setup_shell writes the rc backup through a pre-existing symlink (HIGH, 5/5)
- Arbitrary file overwrite. uninstall_omg already guards this shape - reuse that guard.

### 3.5 fetch_public_download drops the DNS pin for IPv6 literals (MEDIUM, 5/5)
- src/core/http.rs:199 keys resolve_to_addrs on host_str(), which returns BRACKETED [::1] for IPv6,
  never matching reqwest's resolution key. The redirect guard also classifies a narrower IP set.

### 3.6 Fuzzy ranking allocates two lowercase copies per comparison (MEDIUM, 4/5, measured)
- src/core/completion.rs:114-119. ~604ms and ~19M allocations at 500k candidates.
- Fix: hoist the prefix flag into a Vec<bool> computed once.

### 3.7 rust-toolchain.toml scraped as text (MEDIUM, 4/5)
- src/core/completion.rs:188-193. Legal TOML spellings yield no completion.

### 3.8 OMG_PACMAN_CACHE_DIR override is dead for unprivileged users (MEDIUM, 5/5)
- src/core/paths.rs:476 hardcodes `true` where six siblings pass privilege::is_root().

### 3.9 Vendored GPL-3.0 rust-apt exempted by feature-gating, not an exception (MEDIUM, 5/5)

### 3.10 CLI/TUI smaller items
- omg hook accepts powershell/elvish/pwsh then always fails at runtime (5/5).
- omg list --help advertises -A but only -a exists (5/5).
- ShellKind is case-sensitive while handlers are case-insensitive (5/5).
- detect_distro() memoizes, so OMG_TEST_DISTRO set later is ignored (5/5).
- Failure state printed twice in the TEA layer (5/5).
- InfoModel is 557 lines of dead state; omg info bypasses it (5/5).
- Terminal::clear() blocks up to 2s on a DSR round-trip and turns a clean quit into non-zero (5/5).
- transaction_icon misalignment; pad_display_width measures before sanitizing; CJK version padding (4/5).
- Hardcoded command lists in all three shell scripts have drifted from the clap tree (4/5).

### 3.11 Privilege notes
- The env scrub list (src/core/privilege.rs:242-275) is genuinely thorough - 25+ vectors including
  LD_AUDIT, BASH_ENV, NODE_OPTIONS. GCONV_PATH is absent (glibc locale-module hijack); rated 3/5
  because it needs a live exploit.
- Privileged sync writes the pacman DB with no audit record, while package transactions ARE audited
  (alpm_ops.rs:1620/:1624). Auditing exists but is not applied uniformly.
- The documented OMG_ELEVATED contract is not implemented anywhere (3/5).
- PrivilegeChecker whitelist guards nothing (4/5) - dead escalation surface.

## Verified-clean (recorded so they are not re-litigated)

- Panic/unwrap audit of all of src/: a brace-tracking scanner stripped test regions, cutting a naive
  ~1713 unwrap()/~1507 expect() count to 40 real production sites; all 21 secret regexes and all 21
  indicatif templates compiled against the real crates. NO DEFECTS.
- dnf removal relies on the validator, not an argv separator (4/5).
- secrets.yml allowlists correctly scoped; co-location and cache-key suppression safe.
- pacman.conf include cycle guard is correct (5/5).
- The daemon correctly guards against a stale in-flight request repopulating a cleared cache.
- Every #[ignore] in tests/ carries an explicit reason string (4/5).

## Cleared after checking (agent leads that did not survive verification)

- `std::os::unix::fs::MetadataExt` at src/core/usage.rs:487 looks like a Windows compile break, but
  CI targets Linux and macOS only, so it matches the supported platforms.
- validate_package_name allowing `/` is a deliberate trade-off (Go module paths, Debian pkg/file),
  not a plain bug - audit the callers that join rather than widening the validator.
- 12 modules with no referencing test: 3 are test files, not production code.

## Method

- 100 thematic lenses + 324 per-file lenses (all 195 src/*.rs, 108 scripts, 16 workflows).
- 10 agents at a time, unsandboxed so they reach cargo/rustc 1.95 via WSL and compile real
  reproductions rather than speculate.
- Working tree protected: 13,171 files hashed at launch; agents verified to write only under
  .audit/deep-review-20261003/. plan.md is untracked and unstaged.

## Still to come

Waves 7-10 (CI/release, scripts, performance, docs) and the 324 per-file lenses.
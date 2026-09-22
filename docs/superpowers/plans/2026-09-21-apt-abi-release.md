# APT ABI Release Compatibility Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. No subagents. Check off only verified work.

**Goal:** Make verified OMG/OMGD release pairs usable on supported APT 6 and APT 7 systems, including Debian 13 and Ubuntu 26.04, without breaking existing installations or weakening the native backend.

**Architecture:** Retain the existing APT 6 Debian/Ubuntu artifacts. Package the existing Debian Trixie native build as the APT 7 baseline, and validate that same pair on both Trixie and Ubuntu 26.04 before admitting cross-distro reuse. Keep installer and self-update selection consistent with the host's available native ABI. Verify candidates before replacement; incompatibility is an explicit refusal, never a successful installation or a backend downgrade.

**Tech Stack:** Existing Rust native APT backend, Bash installer, Python artifact admission, GitHub Actions, WSL and QEMU.

**Spec:** Issue https://github.com/omg-cli/omg/issues/476 and the approved OMG/OMGD verification plan. This is a discovered release compatibility defect, not a new runtime feature.

## Evidence and research

- Verified CI35600115369 Debian/Ubuntu release artifacts from source3babf5f4 (tree identical to merged mainfa0ba5a7) fail at dynamic loading on Debian13 and Ubuntu26.04 with missing libapt-pkg.so.6.0. Both hosts provide libapt-pkg.so.7.0.
- The same artifact-bound runtime regression passes on Arch and Fedora. Debian/Ubuntu failures do not count as execution coverage.
- Installer detect_distro/select_artifact and Rust self_update::release_target select only by distro identity. Neither selects a native ABI. Trixie CI builds already exist but deliberately skip native-release packaging.
- Primary package contracts: https://packages.debian.org/trixie/libapt-pkg7.0 and https://packages.debian.org/bookworm/libapt-pkg6.0 . A successful source build against APT7 cannot certify an APT6 release artifact.
- Cross-worktree Cargo target reuse produced a proven stale CLI in #475. Use a dedicated target for this worktree or verified hosted binaries. https://github.com/rust-lang/cargo/issues/16642 documents the matching failure mode.

## Constraints and review focus

- Preserve native package/security semantics, checksums, attestations, exact-source provenance and paired CLI/daemon versions.
- Do not fake compatibility by symlinking sonames or silently selecting a less capable feature set.
- No incompatible pair may replace a working installation. Missing artifacts must refuse before mutation.
- Probe known system library locations without shell-evaluating untrusted data; unsupported architectures and unknown ABIs remain explicit failures.
- Both libraries present, neither present, dangling links, wrong architecture, loader failure, mismatched version and hung candidate processes need focused refusal tests.
- Release packaging, mirror/artifact collection, self-update object names, native reuse and QEMU selection must agree. Audit every existing artifact allowlist rather than adding a one-off bypass.
- New ABI fixtures are behavioral evidence only after actual binaries execute native operations and daemon lifecycle checks. Parser selection tests alone are not coverage.
- Primary checkout contains unrelated cleanup edits. Work only in this isolated worktree; merge new main prerequisites before publication.

## Task 1: Package the already-built Trixie pair with verified provenance

Files: `scripts/native-build-artifact.py`, `scripts/test_native_build_artifact.py`, `.github/workflows/ci.yml`, `scripts/test_release_recipe_alignment.py`.

Interface: extend the existing `debian-trixie` platform to the native artifact producer/admission recipe with `debian,pgp,license`, generic CPU and a pinned Trixie image. Preserve the platform identity in provenance and use the matching archive suffix; do not relabel it as bookworm or Ubuntu24.

- [x] Add a failing native recipe/admission regression for Trixie and rejection of incompatible image/feature provenance.
- [x] Route Trixie through the same producer and paired upload as other native platforms, reusing its existing build job.
- [x] Run the native artifact and release-recipe tests; inspect the generated archive/manifest and both ELF dependency sets.
- [x] Execute the exact pair on Debian13 and Ubuntu26.04, including #468's real runtime persistence test. A local build may inform development, but hosted validation is required before closure.

## Task 2: Align release production and consumer selection

Files: `.github/workflows/release.yml`, `scripts/collect-release-artifacts.sh`, `install.sh`, `src/cli/self_update.rs`, existing installer/self-update/release boundary tests.

Interface: one named APT7 baseline artifact is selected only after its host compatibility is established. Existing APT6 names remain stable for supported older hosts. Shared fixture cases must express the same decision table for Bash and Rust.

- [x] Enumerate every archive/object-name consumer and choose the final canonical APT7 suffix consistently with Task1; prove Ubuntu26 compatibility before using the Trixie baseline there.
- [x] Write failing tests for APT6/APT7, both/none installed, architecture refusal and unavailable artifact behavior.
- [x] Implement native ABI detection and exact artifact routing in installer and self-update; preserve requested-version and signer checks.
- [x] Add the matching release pair build, checksum, attestation, collection and mirror entries. Update allowlist regressions rather than relaxing validation.
- [x] Validate Bash/Rust selection parity, workflow recipe alignment and release boundaries.

## Task 3: Refuse unusable candidates before replacing installed binaries

Files: `install.sh`, `tests/installer_security.sh`, `src/cli/self_update.rs` and its existing transaction tests.

Interface: after provenance validation/extraction, perform bounded version/startup validation of both candidates before the first destination write. Retain current owner, symlink, atomic replacement and rollback protections.

- [x] Add failure fixtures for missing loader dependency, wrong version/architecture, absent daemon and hung version command; require unchanged prior CLI and daemon bytes.
- [x] Implement bounded preflight validation and explicit actionable errors. Never treat an unrelated nonzero error as the expected refusal.
- [x] Run installer security and self-update suites, including existing race/rollback cases.

## Task 4: Validate real release behavior and integrate

Files: existing release-smoke/QEMU workflows, platform/coverage policy and relevant installation documentation, as required by the final supported release contract.

- [ ] Cover Debian13 and Ubuntu26 release startup, native query/mutation/refusal, daemon startup and runtime persistence using the verified APT7 pair.
- [ ] Preserve and run legacy APT6 compatibility cases; run all four existing distro gates without retries hiding failures.
- [ ] Confirm failure issue reporting preserves ABI/loader diagnostics with exact artifact and source identities.
- [ ] Review the complete patch and merge only after fresh checks. Close #476 only when all its resolution criteria are demonstrated; keep #468 separate until its hosted runtime oracle passes.
- [ ] Record behavioral evidence without claiming the broader 95% target or independent whole-branch review is complete.

## Implementation evidence

Initial Trixie admission regression failed with `unsupported native recipe` before the producer change. After adding the exact recipe and routing the existing job through packaging: 18 native artifact tests, two release-recipe tests, 41 CI tests and 13 release-boundary tests passed in Debian WSL. These exercise fixture admission and workflow wiring, not a real APT7 release build. No new artifact has been published and no compatibility/runtime credit has been claimed yet.

The installer regression then reproduced successful replacement with an unusable candidate (`Installer accepted unusable pair: loader_error`). The consumer follow-up now probes both authenticated candidates with a ten-second bound and requires exact requested CLI/daemon versions before writing either destination. Fixture cases for CLI/daemon loader failure, wrong CLI version, missing daemon and timeout preserve both prior binaries; the timeout case proves the child is no longer running. The valid pair installs and executes both expected versions. All installer security scenarios, including prior destination-race cases, pass on Arch/Debian/Ubuntu/Fedora WSL. The shared selection fixture now covers APT6, APT7, both-present preference, versioned and dangling links, directories, absence, unpublished Linux architectures and unsupported architectures for both Bash and Rust. These are real installer control-flow tests with fixture binaries, not proof of a published APT7 release.

Final hosted producer evidence: CI run `35654209347` built source `51fb15d2c0f59124b37d3a5bfdb20f1cca116e66`, the merge of main `8ec2b94c1c84f10d08b297818f2fa2dccdf4c942` and exact PR head `f29ed2ba70a57e59de3f9f5c62d658894e545eab`; its tree matches the PR head. Independent admission verified the archive and both binary hashes. The exact Trixie pair requires `libapt-pkg.so.7.0` and passed exact CLI/daemon versions, native APT search, daemon IPC/status, private state, SIGTERM socket cleanup, and Node 24.21.0 installation/execution on Debian13 and Ubuntu26.04. All four hosted QEMU guests admitted 183 selected cases: 180 executed and passed, zero failures/blocks/harness errors, and three declared CLI-shape skips. Producer PR477 merged as `0f4b48b8e15e76e9d0f8992b4a9de4a0506c1d37`; consumer publication and hosted release-smoke validation remain separate.

Rust preflight evidence: the new regression first failed because unusable/hung candidates were accepted. After implementation, all 40 self-update tests pass using a dedicated Cargo target, including missing/nonregular/nonexecutable/malformed candidates, CLI/daemon loader/version refusal, bounded output, timeout child reaping, existing transaction rollback, shared APT ABI selection and the successful production blocking-worker/runtime bridge. Strict Clippy for the library and tests passes. No complete resolution of #476 is claimed until the hosted consumer release workflow and smoke lanes pass.

Release production/collection follow-up: the existing Debian release job now has pinned Bookworm and Trixie matrix entries, retaining one common recipe and distinct artifact names. Executable packaging fixtures verify both CLI/daemon bytes and checksum sidecars for both entries. Collection requires all six platform archives plus checksums and SBOM; the regression first rejected the valid APT7 bundle and accepted an incomplete APT6-only bundle, then passed after the allowlist correction. Duplicate, corrupt, unexpected and missing Trixie artifacts remain rejected. Twenty-three release selection, collection, recipe, rollback and boundary tests pass on Debian WSL. Four staged smoke lanes require APT6 on Debian12/Ubuntu24.04 and APT7 on Debian13/Ubuntu26.04 before release publication. The canonical omg-web installer copy is byte-identical in draft PR117. A fresh hosted consumer dry run remains pending.

Rollback follow-up: r2-rollback.sh now requires the APT7 archive and sidecar before moving latest-version. Historical releases can use explicit --allow-legacy-apt6 with a warning that APT7-only clients cannot install them; the incident runbook documents this tradeoff. Executable fake-Wrangler tests reproduced the prior acceptance of missing APT7 artifacts. All five scenarios now pass, including non-dry-run refusal with no object-put call, missing sidecar, complete bundle, explicit historical exception, and continued APT6 requirements. No Cloudflare network operations or marker changes were performed.

# CI/CD review — 2026-09-19

> **Who this page is for:** OMG maintainers and contributors. It documents a dated continuous-integration review.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Status: researched recommendations; no workflow changes applied.

Follow-up: [deep research and measured backlog](ci-cd-deep-research-2026-09-19.md) expands this review. It corrects the source-PR release-build count to eleven (Docker compiles another binary) and replaces blanket per-revision target caching with a measured choice between dependency caching and selective snapshots.

Reviewed local main `27cc8f8043aaf38aa2cd10dfc4502bad5e141a4c`, latest PR #436 head `a6fe1e314031d479350233bcffdea28043e8f63b`, recent issues and hosted job logs. Goal: reduce duplicate compilation and runner consumption while retaining platform, daemon, security, coverage and exact-commit release checks.

## Current issues and PR

- [PR #436](https://github.com/omg-cli/omg/pull/436) is open and not draft, although its description says to keep it draft until checks and inventory review finish. CI, staged QEMU, Docker E2E, CodeQL, secrets and release-smoke returned success for the queried head; coverage failed. This is a targeted CI/inventory review, not an exhaustive review of every new Rust path.
- [Coverage failure](https://github.com/omg-cli/omg/actions/runs/35126267163/job/104896015840): `behavior_inventory_runs_in_hermetic_state` fails twice with `env-export-missing-lock: expected exit 1, got 0`. The inventory executes `env-capture` first, and `tests/cli_comprehensive.rs:919` creates one shared project outside the row loop. The new missing-lock row therefore encounters a lock created by an earlier row. Preserve the expected failure and use a genuinely empty fixture, or put the missing-state case before capture with an explicit ordering regression. Do not remove coverage or change the expected exit to success.
- [Issue #437](https://github.com/omg-cli/omg/issues/437): the [Arch job](https://github.com/omg-cli/omg/actions/runs/35430795824/job/105864920509) failed pulling the pinned Debian controller image because the Docker Hub authentication request timed out. This happened before guest startup; it is not evidence of a daemon or package-lifecycle regression. A bounded, fail-closed retry of the pinned controller pull is worth implementing separately.
- [Issue #438](https://github.com/omg-cli/omg/issues/438) is the aggregate failure from the same run. Its Ubuntu label does not establish an Ubuntu guest failure: the report cites the Arch job, and workflow aggregate reporting uses an Ubuntu identity. Prefer one actionable case issue with aggregate context; retain aggregate issues when per-case evidence is unavailable or invalid.
- Recent merged work already includes documentation-only PR classification and the Quick Gate target-directory correction (#431), plus independent QEMU distro scheduling and verified base-image caching (#432). Do not repeat those changes. #430 restored GitHub-hosted runners after #429's provider experiment.

## Confirmed overlap and limitations

| Area | Evidence | Action |
| --- | --- | --- |
| Ubuntu release build | CI and QEMU both use Ubuntu 24.04, Rust 1.95.0 and `--release --no-default-features --features debian,pgp,license --locked` | Best first candidate for one build feeding both consumers |
| Linux builds | CI has Arch, Debian bookworm, Debian trixie, Fedora and Ubuntu; QEMU rebuilds four x64 distros | Four overlapping distro build paths, but not yet proven byte-equivalent |
| Unit tests | Both CI and staged QEMU run `--lib --bins` | Compare selected tests and execution contracts before consolidating: CI uses nextest, QEMU serial libtest, and dev/test LTO environments differ |
| Quick Gate | `Makefile:276` cargo-checks portable targets; Portable Rust Clippy checks the same targets in a separate cache | Keep formatting, shell and workflow checks early; consider moving portable compilation ownership to the Portable job |
| Main pushes | Classifier returns full checks for every non-PR event; eight release prerequisites require exact push evidence | Documentation merges still trigger substantial builds by design; changing this requires a coherent release-candidate selection policy |
| Release publishing | Five release builds run after CI and QEMU pass | Later promote verified same-commit artifacts; do not blindly consume PR artifacts or weaken tag/source attestation |
| Compiler caches | CI matrix/intersection, coverage, Docker E2E and benchmark caches key target data only on lockfile plus a coarse prefix | Refresh source-dependent compiler caches with compatibility prefixes and revision suffixes |

On PR #436, the [CI Ubuntu job](https://github.com/omg-cli/omg/actions/runs/35126267165/job/104898087060) release-build step ran approximately 17:14:45–17:20:29 UTC (5m44s). The [QEMU Ubuntu build](https://github.com/omg-cli/omg/actions/runs/35126267432/job/104896091967) release-build step ran approximately 17:17:40–17:24:02 (6m22s). One shared build could avoid roughly one of these build intervals in this sample, plus duplicated setup. These are observed runner-time costs, not guaranteed elapsed-time or billing savings. Cache conditions differ.

Ordinary source PRs currently execute six release-profile CI builds plus four staged QEMU builds. Version publication adds five more release builds, and main also runs the benchmark build. Coverage instrumentation and CodeQL analysis add distinct work and must not be treated as interchangeable with ordinary test execution.

Arch/Fedora/Debian QEMU build steps set `target-cpu=x86-64-v2`; CI does not. The release workflow explicitly sets that flag for Arch, but not Debian/Fedora. Normalize intended compiler flags before treating those outputs as equivalent. Debian trixie provides a distinct native APT ABI check and should remain covered.

## Recommended first patch: compiler cache refresh

This is bounded configuration work. Files: `.github/workflows/ci.yml`, `coverage.yml`, `docker-e2e.yml`, `benchmark.yml`, plus focused cache-contract checks in `scripts/`.

1. Leave dependency-download caches keyed by dependency identity.
2. For raw target caches, use a versioned compatibility prefix containing distro/architecture, toolchain, build configuration and lock identity; append the commit SHA to the exact save key.
3. Restore the newest cache within that compatible prefix when the revision changes. Keep coverage targets distinct from ordinary targets. Avoid broad fallback across incompatible toolchain/image/feature configurations.
4. Preserve existing check commands, event selection, required status names and release gates. Bound retention/storage expectations: revision keys improve freshness but increase cache entries, so measure restore/upload size and eviction.
5. Verify cache-key behavior for source-only changes, lock/toolchain/image changes, identical revisions and incompatible configurations; run actionlint and existing classifier/required-result/release-boundary regressions. Compare two successive hosted source revisions before claiming a speedup.

[GitHub cache documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching) confirms that existing cache contents cannot be changed and a new key is needed to save refreshed data. The coverage sample restored the exact lockfile-only target key. This design diagnosis does not establish a measured cache speedup yet.

## Subsequent changes, separately reviewed

1. Correct #436's fixture and verify the exact failing integration test plus hosted coverage.
2. Add bounded controller-image pull retries and improve aggregate failure attribution. Retain image digest, QEMU security floor, KVM, isolation and provenance checks.
3. Shorten Quick Gate's serial compilation path while preserving portable Clippy and fuzz compilation in explicitly required jobs. Keep local developer Make targets useful; do not silently weaken them.
4. Pilot one Ubuntu build/test producer supplying CI verification and the QEMU guest. Require the same commit, feature/profile/toolchain contract, both `omg` and `omgd`, artifact checksums, and rejection of missing or failed producers. Compare test inventories before deleting either execution path. Preserve job result aggregation and all daemon/security regressions.
5. Expand only after the pilot passes. Artifact promotion into a published release changes the trust boundary and signer/source-ref contract; design and verify it independently.

Concurrency also needs a consistent release policy. CI preserves running main jobs, while several prerequisite workflows cancel superseded main runs. Keeping one side alive while canceling its required evidence can waste remaining CI work and prevent tagging. Conversely, blanket cancellation can strand a version bump. Also, `cancel-in-progress: false` alone does not guarantee every queued commit is retained under default concurrency behavior. See [GitHub concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency). Choose explicit release candidates and define cancellation together with evidence selection before changing this.

## Validation and scope

Read workflow definitions, Make recipes, classifier and release-evidence helper, the existing QEMU efficiency plan, current PR diff/inventory, and hosted logs. No builds, reruns, comments, merges, issue edits, or workflow behavior changes were made. This report records a reviewable first patch and the prerequisites for the larger consolidation; it does not claim the pipeline is optimized yet.

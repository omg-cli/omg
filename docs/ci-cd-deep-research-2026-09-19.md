# CI/CD deep research — 2026-09-19

> **Who this page is for:** OMG maintainers and contributors. It documents a dated research note.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

## Decision

The largest improvement is one verified producer for each compatible build, consumed by multiple checks. More cache layers alone will not solve repeated release linking. Start with measurement, Docker layer reuse, cache-size reductions and gate scheduling; consolidate Ubuntu first, then expand after proving compiler, test and artifact contracts equivalent.

This is a research result and proposed design, not an implemented optimization. No workflow, ruleset, deployment, subscription or release was changed. There is no defensible claim that nothing remains to improve: dependencies, runner images and workloads evolve. The acceptance criteria below define when the known backlog is exhausted or explicitly deferred.

## Method and evidence

Exa: 15 searches across six workstreams (orchestration; Rust/build caches; tests/coverage; containers; security/artifact delivery; measurement/maintenance), requesting and returning 76 result entries. These reduce to 67 normalized URL strings, with further semantic duplicates/redirects. Search matches were screened; they are not 76 independently verified authorities. Recommendations use primary upstream documentation, including the repository's pinned rust-cache revision. Nine distinct primary pages were also fetched directly; two unsuccessful nextest URLs were replaced with their correct documented locations.

Reviewed all 16 workflow files through this and the preceding review, relevant Cargo/nextest/Docker/Make configuration, QEMU setup, the live main ruleset, and hosted job/step timestamps. Raw job measurements are in [the CSV](ci-cd-research-2026-09-19-jobs.csv); search queries and candidate URLs are in [the source ledger](ci-cd-research-2026-09-19-sources.json). Previous issue diagnoses are in [the initial review](ci-cd-review-2026-09-19.md).

Baseline: local main `27cc8f8043aaf38aa2cd10dfc4502bad5e141a4c`; PR #436 head `a6fe1e314031d479350233bcffdea28043e8f63b`, hosted runs from September 16. One sample supports prioritization, not statistical performance claims. Queue time here is job creation to job start; upstream dependency waits can occur before a job is created and are measured separately through the workflow graph.

| Workflow | Sum of non-skipped job time | First job start to last completion | Run |
| --- | ---: | ---: | --- |
| CI | 111.3 min | 27.1 min | [35126267165](https://github.com/omg-cli/omg/actions/runs/35126267165) |
| QEMU | 61.6 min | 23.6 min | [35126267432](https://github.com/omg-cli/omg/actions/runs/35126267432) |
| Docker E2E | 10.3 min | 10.3 min | [35126267170](https://github.com/omg-cli/omg/actions/runs/35126267170) |
| Coverage, failed | 13.6 min | 13.7 min | [35126267163](https://github.com/omg-cli/omg/actions/runs/35126267163) |
| CodeQL | 13.7 min | 13.0 min | [35126267167](https://github.com/omg-cli/omg/actions/runs/35126267167) |
| Secrets | 0.6 min | 0.5 min | [35126267197](https://github.com/omg-cli/omg/actions/runs/35126267197) |
| Release smoke | 5.4 min | 1.8 min | [35126267168](https://github.com/omg-cli/omg/actions/runs/35126267168) |
| **Total** | **216.4 min** | **Do not sum parallel workflows** | |

These are elapsed job-minutes, not billed minutes. The repository is public; standard GitHub-hosted runner execution is currently free under [GitHub's policy](https://docs.github.com/en/billing/concepts/product-billing/github-actions). Storage, larger runners and external providers need separate accounting. Saving time here primarily improves feedback, resource use, reliability and capacity; a dollar saving cannot be inferred from this table.

## Corrections and deeper findings

1. **Eleven release builds, not ten:** six CI platform builds, four staged QEMU builds, and an additional Arch release build inside `Dockerfile.arch-e2e`. Docker's build step took 472 seconds, most of its 620-second job. Its host Cargo cache does not cache Docker layers; `.dockerignore` excludes host `target`.
2. **Cache saving is on the critical path:** Debian and trixie spent 184 and 169 seconds in `Post Cache target`. A strategy that saves more target snapshots can make the pipeline slower. Coverage restored its target in 61 seconds. Follow-up inspection of Debian job `104898087179` found a 1,465,511,213-byte compressed target archive; reported transfer ran from 17:34:26 to 17:34:30 UTC, while the save step began about three minutes earlier. The dominant cost is packaging/compression before transfer, not upload bandwidth. Measure bytes and transfer time before increasing save frequency.
3. **Quick Gate is not cheap:** its recipe took 335 seconds and the job 366 seconds before CI platform jobs started. Portable Clippy subsequently type-checks the same portable target set with separate caching. Fuzz compilation also sits in this shared serial prerequisite.
4. **Same feature names are insufficient proof of equivalence:** CI disables dev/test LTO through environment overrides; QEMU has different execution semantics and sets x86-64-v2 on container release builds. Native library versions, root/non-root execution and nextest versus serial libtest matter.
5. **Docker test conversion has a trap:** the current libtest process uses `OnceLock` to build its image once. Moving this test binary to nextest can build the image separately in each test process unless image setup is first moved outside test execution.
6. **CodeQL already avoids a full product build:** Rust uses `build-mode: none`; upstream says Rust analysis still uses rust-analyzer and compiles build scripts/macros. The observed analysis step was 750 seconds. Removing the Rust toolchain or adding a redundant release build is not a valid shortcut. [CodeQL Rust behavior](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages).
7. **The live main ruleset requires two checks:** `CI Success` and `Generate Coverage Report`, with strict up-to-date checks. The inspected ruleset has no merge-queue rule. Both required workflows already have `merge_group` triggers; missing triggers in optional workflows are not a demonstrated current merge-queue bug. [Live ruleset](https://github.com/omg-cli/omg/rules/23399194).

## Ranked opportunities

### Follow-up validation on the fixture fix

PR #436 revision `f2d06c49360c74abacdef9198954dd5624c1dc16` isolates the missing-lock and missing-manifest inventory probes from earlier rows. In [coverage run 35488596487](https://github.com/omg-cli/omg/actions/runs/35488596487), all 2,849 selected tests passed (43 skipped by existing selection); `behavior_inventory_runs_in_hermetic_state` passed in 11.659 seconds. The whole test execution took 447.636 seconds after 10m46s of instrumented compilation. Three tests received slow notices: `version_detection::test_rust_toolchain_toml_detection`, `prop_info_never_crashes`, and `prop_version_aliases`. Investigate their subprocess/runtime-resolution fixtures before changing test counts or timeouts.

The same revision's [Quick Gate](https://github.com/omg-cli/omg/actions/runs/35488596488/job/106019397918) took 316 seconds overall. Its shared recipe took 287 seconds: portable `cargo check` accounted for 3m32s and fuzz checking for 1m12s. This is a second observation of the serial compilation bottleneck, not yet a before/after optimization measurement.

[Docker E2E](https://github.com/omg-cli/omg/actions/runs/35488596504/job/106019397862) restored an 866,206,011-byte host cache, but the independent release compilation inside the Docker build still took 9m05s. All ten E2E tests passed. External layer caching must preserve compatible dependency build layers across source changes; caching only setup layers would leave this major cost intact.

Priority A is actionable groundwork and bounded changes. Priority B changes producer/consumer relationships and needs an architecture review. Priority C is an experiment or lower-return maintenance item. Estimated impact is qualitative unless a measured interval is stated.

### A — first implementation batches

| ID | Change and repository location | Evidence / expected benefit | Validation and limit |
| --- | --- | --- | --- |
| A1 | Emit compact job/build/cache/test metrics from existing workflows | Establish p50/p95 feedback time, total job-minutes, cache transfer size/time, dirty Cargo units and retries | Start with API-derived timestamps and existing QEMU `--timings`; add timing output to other build owners. Do not repeatedly rerun the whole matrix just to gather data |
| A2 | Separate cheap Quick Gate checks from portable/fuzz compilation (`ci.yml`, Makefile) | Removes a 5m35s serial recipe from ahead of every platform lane; Portable Clippy covers portable type-checking | Preserve formatting, shell safety, Python fixtures, installer checks and fuzz compilation in required jobs. Update aggregate dependencies and behavioral gate tests; retain useful local Make targets |
| A3 | Measure then replace oversized/raw target cache policy (CI, coverage, benchmark, Docker) | Cache uploads alone cost 5m53s across two Debian jobs in this sample | Prefer dependency caching for frequently changing workspace crates. Test selective revision snapshots only where compile savings exceed restore/save overhead. Include toolchain, target, image/native dependency contract, features and flags; keep coverage separate |
| A4 | Build Docker E2E image explicitly with Buildx cache, then let tests consume it | Removes repeated 7m52s cold image compilation on compatible reruns; provides observable cache hits | Use a dedicated cache scope and compatible BuildKit v2 tooling. Load the locally built image into Docker; preserve a local-test build fallback. Assert exact revision/image identity, not merely that a tag exists |
| A5 | Retry only transient pinned-controller pulls (`benchmark-qemu.sh`) | The latest Arch failure was Docker Hub auth timeout before guest startup | Bounded attempts/backoff and total timeout; fail after exhaustion. Test transient recovery, permanent failure, wrong digest and unchanged isolation. Never retry away product-test failures |
| A6 | Tune coverage reporting and persist compact test results (`coverage.yml`, nextest config) | LCOV, HTML and summary took 29+28+27 seconds after a single test pass | Tests already run once. Retain authoritative LCOV; consider HTML only on failures/manual diagnosis and derive a validated summary from the report. Preserve cleanup of old coverage data and report correctness |
| A7 | Classify retry policy and expose flaky tests (`.config/nextest.toml`) | CI allows two retries generally; coverage uses default profile with one retry | Keep security/concurrency regressions first-failure blocking. Permit bounded retries only for classified external transients; record first-attempt failures. Pin nextest before adopting version-specific flaky-failure features |
| A8 | Stop recompressing `.tar.gz` artifacts and tier retention | QEMU packages are uploaded with default compression despite already being compressed | Use `compression-level: 0` for compressed archives; retain compression for text. Validate checksums/executable preservation. Candidate retention must exceed the permitted promotion window; retain failure evidence longer than disposable successful intermediates |
| A9 | Pin CI tools coherently | Several install-action steps pin the installer action but request floating nextest/llvm-cov/audit/deny tools | Record versions in evidence and update through reviewed maintenance batches. Do not confuse an action SHA with a pinned downloaded tool version |

Sources: [Cargo timings](https://doc.rust-lang.org/stable/cargo/reference/timings.html), [pinned rust-cache behavior](https://github.com/Swatinem/rust-cache/blob/6323deb102c322ba6fcbdcafc7e3dddab59af2b6/README.md), [Docker Actions caching](https://docs.docker.com/build/ci/github-actions/cache/), [BuildKit cache scopes](https://docs.docker.com/build/cache/backends/gha/), [llvm-cov reporting/cleaning](https://github.com/taiki-e/cargo-llvm-cov), [nextest retries](https://nexte.st/docs/features/retries/), [artifact compression](https://github.com/actions/upload-artifact).

### B — larger improvements

| ID | Proposed change | Benefit and prerequisites |
| --- | --- | --- |
| B1 | One compatible build producer per distro/revision | Pilot Ubuntu: CI release compilation 344s versus QEMU 382s. Share the resulting pair of binaries and archive with CI smoke and QEMU. Record commit, recipe, toolchain, flags, target, native libraries and digest. Do not claim all four Linux builds interchangeable yet |
| B2 | Give unit, integration, coverage and guest checks explicit owners | Remove repeated unit execution only after comparing selected tests, features, privilege, process model and ordering. Preserve both execution modes where one catches stateful/process-lifetime bugs the other cannot |
| B3 | Start the sandbox regression when the Arch producer completes | `sandbox-cancellation` currently waits on the entire Linux matrix, including slower Debian/cache-save jobs. Split the Arch producer dependency if measurements justify it; keep every platform required at the final aggregate |
| B4 | Introduce an explicit release-candidate lifecycle | Current main CI keeps running while prerequisite workflows may cancel its evidence. Cancel superseded ordinary validation consistently; retain chosen release candidates. Keep exact-commit push evidence and immutable tags until a replacement policy is formally implemented |
| B5 | Replace runner-held polling with event-driven readiness | `release-tag` and `gate-on-ci` can occupy runners while `gh run watch` waits. Prefer dependency scheduling in one orchestration graph or a short trusted completion coordinator. Revalidate every required result, run attempt and commit immediately before tagging/publication; handle simultaneous completion and retries idempotently |
| B6 | Reuse final candidate artifacts for release publication | Remove five later release compilations only after provenance is designed. Existing installers demand `release.yml` signer and a tag source ref. Re-attesting arbitrary PR artifacts is unacceptable. Easiest first phase: share builds within validation and keep the current trusted tag build |
| B7 | Bake maintained build/controller images | QEMU installs its controller toolset in every guest lane; distro jobs repeatedly install compilers/libraries. Use reviewed digest-pinned images with controlled refresh, package manifest/SBOM, security-floor checks, fallback and expiry. Cached package-install layers do not automatically refresh with security updates |
| B8 | Centralize change classification and matrix metadata | Share one small, reviewed capability manifest across CI/QEMU/release recipes to prevent feature/flag/image drift. Keep job-level skips and always-running required aggregates. Unknown paths and failed classification select full checks. Distinguish docs-only PR optimization from the current all-main-commits release policy |

Sources: [reusable builds and attestation identities](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating), [required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks), [Docker cache invalidation](https://docs.docker.com/build/cache/invalidation/), [GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

### C — measured experiments and maintenance

| ID | Candidate | Decision rule |
| --- | --- | --- |
| C1 | Cheaper non-release debug info / dependency optimization | `profile.dev` has full debug info and dependency opt-level 2. Compare limited debug info and dependency opt-level 0/1 against compile plus test time and useful backtraces. Keep release and security-sensitive behavior unchanged |
| C2 | ThinLTO/codegen-unit/linker experiments | Release uses fat LTO and one codegen unit. Benchmark runtime latency, binary size and unwind/security regressions before changing it. The repository records historical rust-lld/LTO concerns; do not replace gcc unconditionally. The bench profile's 'fast' comment is misleading: it inherits release fat LTO and adds debug info |
| C3 | Tune Cargo job count and concurrency to resources | `.cargo/config.toml` hard-codes five jobs, Docker build uses two, QEMU controller caps two CPUs/3 GiB. Measure actual CPUs, memory, peak RSS and contention. Larger paid runners are not the default recommendation for this public repository |
| C4 | Build-once nextest archives, then selective sharding | Use only if test execution dominates after compilation is consolidated. Archive once, shard execution, preserve source revision/ABI and test union. Each shard rebuilding the suite increases cost; cross-distro native tests remain distinct |
| C5 | Resource-specific test groups | Replace broad serialization only after auditing shared ports, files and daemons. Nextest runs one process per test; in-process mutexes/OnceLock do not synchronize different tests. Prefer isolated fixtures, random ports and temporary sockets |
| C6 | Reduce security orchestration overhead carefully | Four `cargo deny check` invocations can potentially become one combined check with equivalent diagnostics. Audit/deny overlap requires a policy-equivalence fixture before removing either. Keep Gitleaks and verified TruffleHog: together they cost only 35 seconds in this sample and detect different things |
| C7 | Tune CodeQL after profiling extraction/query phases | Preserve Rust and Actions analysis. Investigate supported dependency caching for the pinned action/language and redundant file selection only with analyzer evidence. Do not reduce query coverage solely to make 750s disappear |
| C8 | Control dependency-bot update bursts | Renovate already groups Cargo packages and limits open PRs to five, but rebases whenever behind main. Strict up-to-date checks explain some rebuilds. Consider batching action updates and limiting branch/rebase pushes; do not blindly use conflicted-only rebasing or delay urgent vulnerability fixes |
| C9 | Reduce redundant helper checks and history fetches | Quick Gate, benchmark and QEMU repeat some helper fixtures; retain distinct privileged-host probes. Share ownership in the final graph. Fetch only needed objects where proven sufficient; secret scanners/history generation and merge-base classification need deliberate history handling |
| C10 | Stagger heavy scheduled work | Benchmark and mutation start at Sunday midnight, audit also at midnight. Offset schedules to reduce shared capacity/network bursts. Keep fuzz/mutation periodic coverage even with no source changes: dependencies, external services and newly found vulnerabilities still change |

Sources: [Cargo performance tradeoffs](https://doc.rust-lang.org/stable/cargo/guide/build-performance.html), [Cargo profiles](https://doc.rust-lang.org/cargo/reference/profiles.html), [nextest archives](https://nexte.st/docs/ci-features/archiving/), [partitioning](https://nexte.st/docs/ci-features/partitioning/), [test groups](https://nexte.st/docs/configuration/test-groups/), [cargo-deny checks](https://embarkstudios.github.io/cargo-deny/cli/check.html), [Renovate configuration](https://docs.renovatebot.com/configuration-options/).

## Options rejected or deferred

- **Blanket per-SHA target caching:** revises the initial review's default recommendation. It refreshes immutable snapshots but cannot guarantee warm workspace builds because Cargo tracks file mtimes. It can also add minutes of uploads and cause eviction. Use dependency caching or selective snapshots based on net measurements. [Cargo fingerprints](https://doc.rust-lang.org/stable/nightly-rustc/cargo/core/compiler/fingerprint/index.html).
- **Sccache everywhere:** it cannot cache crates invoking the system linker, including binaries and proc macros. It cannot eliminate the expensive repeated release links. Benchmark already enables sccache. Add it elsewhere only with hit/miss reasons and net benefit. [Upstream Rust limitations](https://github.com/mozilla/sccache/blob/main/docs/Rust.md).
- **Cache-mount-only Docker fix:** BuildKit's GHA cache does not preserve cache mounts automatically. Prefer proper layer export before introducing cache-dance tools. Scope images independently and include cache transfer costs.
- **Skip coverage because unit tests passed:** coverage currently found #436's real inventory-fixture failure that CI's lib/bin selection missed. Retain that integration test and failure gate.
- **Treat all distributions or execution modes as equivalent:** Debian bookworm/trixie and Ubuntu native APT environments remain meaningful. Published smoke tests validate distribution/provenance paths that staged guests do not.
- **Nightly compiler tricks or dependency surgery as first steps:** unstable compiler options and removing crypto features are higher-risk product changes. First eliminate duplicated builds and oversized caches.
- **Assume `cancel-in-progress: false` retains every queued release:** current GitHub docs expose `queue: max` for up to 100 pending runs; it cannot combine with `cancel-in-progress: true`. Verify support in the repository's linter/platform before adoption, and explicitly choose FIFO release processing versus latest-candidate semantics.
- **Automatically expand branch-required checks:** the two live aggregate names must remain reliable. A broader merge policy can be considered independently; it is not necessary to obtain the proposed savings.

## Proposed architecture and rollout

The target graph is: classify plus cheap checks → compatible build producers → independent consumers (native tests, sandbox, Docker, QEMU, performance checks) → fail-closed aggregates. Coverage and CodeQL remain distinct consumers with their own instrumentation/analysis needs. A trusted release coordinator accepts only an explicit candidate with complete immutable evidence.

Use a reusable workflow only when it actually shares a recipe. Invoking the same reusable workflow twice still executes the build twice; reuse must pass artifacts or test archives between consumers. Keep untrusted PR execution read-only. Keep distro guests independent rather than creating a new all-distros scheduling barrier.

1. Correct #436's shared-fixture failure and the controller-pull reliability issue; retain the exact expected tests.
2. Add compact measurement and pin tools; implement A2/A3/A4/A6/A8 as separately reviewable changes with focused regression checks. Cache policy is selected by net measurements, not predetermined as per-SHA snapshots.
3. Pilot B1 on Ubuntu, prove artifact identity and selected-test parity, then compare hosted runs. Extend to other distros only after flags/native environments are normalized.
4. Review candidate selection, concurrency and event-driven release coordination together. Preserve existing tag/signature verification until its replacement is proven end to end.
5. Run C experiments only when the new measurements justify them. Keep a small performance budget rather than adding more services by default.

## Acceptance: no known unjustified waste

Measure comparable source-only, dependency, workflow and documentation changes separately, with warm/cold cache labels. Use routine runs first; obtain at least five comparable observations for a provisional median. Report p95 only with a materially larger sample (target 20+) and include failures/cancellations rather than hiding them.

- Every build has a unique documented tuple: revision, target/architecture, native environment, features, compiler flags, profile and instrumentation. Duplicate tuples have an explicit reason or share an artifact.
- Every test family has an owner; before/after test inventories prove no cases, ignored integration jobs, daemon binaries or security fixtures disappeared. Failed/cancelled/missing producers reject aggregates.
- Cache policy shows positive net benefit after restore, validation, upload and storage/eviction costs. Cold runs and missing/corrupt caches still work safely.
- Required statuses report for docs, source, manual and applicable merge-group events; classifier failures never silently bypass checks.
- Release evidence is tied to the exact candidate and run attempt, with verified artifact digests and preserved signer/tag contracts. Test superseding pushes, concurrent completions, failed reruns, expired artifacts and publication retry.
- Paired measurements improve either median/p95 feedback or total job-minutes without unacceptable regression in the other. Set numerical budgets after the sample is representative; do not promise a percentage from one run.
- Every item above is implemented and measured, rejected with evidence, or deferred with an explicit cost/risk reason. Remaining unknowns are visible: cache occupancy/quota, broader timing distribution, CodeQL phase breakdown, historical flake rate and true compiler-unit equivalence.

This produces an optimized, observable pipeline with a finite known backlog. It does not pretend future improvement is impossible.

## Verified implementation: 2026-09-20

PR #436's fixture correction passed all seven workflows before the optimization started. Draft [PR #439](https://github.com/omg-cli/omg/pull/439), commit `eb1605978ac6b9ee6e8cf56ab651685088b7a6d8`, implements the Quick Gate split. It removes repeated portable compilation and moves fuzz compilation into required Portable Rust; local developer compilation checks and required aggregate behavior remain intact.

All four triggered workflows passed: [CI](https://github.com/omg-cli/omg/actions/runs/35490162129), [Coverage](https://github.com/omg-cli/omg/actions/runs/35490162133), CodeQL and Secret Scanning. Independent review found no actionable issues and reran the 33 passing CI policy tests.

| Observed job/step | Before | After |
| --- | ---: | ---: |
| Quick Gate | 316s | 18s |
| Quick Gate recipe | 287s | 4s |
| Portable Rust | 617s | 706s |

The moved fuzz check passed in 84 seconds. The gate releases platform work about five minutes earlier in these observations. This single-run comparison spans nearby revisions and potentially different runner/cache conditions; it is not a statistical end-to-end speedup claim. Neither PR has been merged. The Docker compilation and cache packaging opportunities above remain outstanding.

## Follow-up audit: 2026-09-20

- [PR #440](https://github.com/omg-cli/omg/pull/440) implements bounded transient controller pulls, preserves exported pull diagnostics, suppresses duplicate aggregate issues when detailed failure evidence exists, and disables compression for staged gzip archives. The first hosted preflight exposed a fake-Docker fixture without `pull` support; commit `f6cf0faa97daa8fc8ffa93471033d32e8bd7c6ad` fixes that fixture and adds a pull-failure lifecycle case. The corrected Linux QEMU preflight passed; full hosted jobs are pending.
- Live cache usage API reported 16,097,547,642 bytes across 18 active entries. The immediately following listing had 20 entries as runs changed state. Two PR-specific coverage caches were 2.44/2.47 GB; four PR #439 distro targets were 1.35–1.46 GB each. This is storage occupancy, not a claim about billing or configured quota. PR-scoped cache proliferation must be included in cache-policy measurements.
- Docker E2E's Rust source imports only `std` and has ten tests. Its baseline host Cargo build took 27.07 seconds after restoring 866,206,011 bytes; the image then spent 547.3 seconds on its separate release-build layer. Pilot compiling that unchanged test source with `rustc --edition=2024 --test`, retaining libtest's ignored/serial flags and all ten cases, before adding a complex image-cache system. Remove the unnecessary host Cargo cache only after hosted parity succeeds. The container remains responsible for the actual application build.
- [Rust's documented test mode](https://doc.rust-lang.org/rustc/tests/) creates the standard libtest harness directly. No application code is imported by this Docker driver, so direct rustc compilation can eliminate host dependency work without substituting the tested application binary. Validation must compare the test inventory and retain failure propagation.
- [Docker layer-cache behavior](https://docs.docker.com/build/cache/optimize/) means Buildx alone cannot preserve compilation across changes to `COPY . .`. A later image-cache pilot needs dependency layers or a maintained compile cache, explicit native-environment compatibility, and a security-refresh policy. Do not claim the nine-minute image build is solved by the standalone harness change.
- [rust-cache](https://github.com/Swatinem/rust-cache) defaults to dependency caching, keys compiler/environment inputs, and supports conditional saves. Evaluate replacing raw whole-target caches with this existing pinned action, including distro/image/features in the compatibility contract, before adding per-revision multi-GB snapshots. Keep coverage instrumentation separate.
- Another scheduled failure was found: [Mutation Testing run 35484109922](https://github.com/omg-cli/omg/actions/runs/35484109922). It found 217 candidate mutants, spent 515 seconds building the baseline, then failed baseline tests after 16 seconds. `tests/coverage_15.rs::init_defaults_writes_omg_lock_in_working_directory` assumes a backend-enabled capture, but the workflow builds only `pgp,license`; `explicit_packages_for_fingerprint` deliberately rejects that configuration. Correct the test to exercise each compiled-backend contract; do not skip the entire integration suite or suppress exit 4. Mutation score was never measured in this failed run.
- Mutation cache limitation: the tool uses scratch build directories and excludes root `target` by default ([official build-directory documentation](https://mutants.rs/build-dirs.html)). The workflow's restored root target cache therefore cannot be assumed to speed these builds. Do not switch to in-place mutation or copy large targets without measurement and recovery design. Its full test set, score threshold and failure behavior stay intact while fixing the baseline.
- Audit also invokes `cargo deny check` four times for advisories, licenses, bans and sources. A single command can potentially retain all categories with less metadata/startup work; verify the pinned tool's CLI and summary behavior before changing it. This is lower priority than the broken baseline and duplicate compilation.

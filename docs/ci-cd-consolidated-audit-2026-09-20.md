# Consolidated CI/CD audit and QEMU verification roadmap

> **Who this page is for:** OMG maintainers and contributors. It documents a dated continuous-integration audit.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

All remaining changes from this audit are collected in PR #440. PR #439 already
merged the fast initial gate; that was one bottleneck, not the whole optimization.
The final combined revision must pass hosted checks before integration.

## Evidence and implemented changes

The earlier source-PR sample used 216.4 elapsed job-minutes across seven workflows.
This is resource time, not a bill or the sum of wall-clock feedback times. One
sample cannot establish p50/p95 or predict the speedup of these changes.

| Area | Evidence | Change |
| --- | --- | --- |
| Initial gate | 316s before, 18s after on nearby revisions | Already merged in #439: keep syntax/policy checks cheap; required Portable Rust owns fuzz/type checking |
| Native CI caches | Debian target archive 1.47 GB; save packaging about three minutes | Cache dependencies rather than project executables; separate distro image/features, compiler/config and lockfile compatibility |
| Coverage | About 2.45 GB cached; HTML generation 28s in sample | Cache instrumented dependencies separately; retain LCOV and summary; generate HTML on failure/manual diagnosis |
| Docker host | 866,206,011-byte cache; 27.07s host compilation | Compile the std-only libtest driver directly; keep every Docker test serial in the same process |
| Docker image | Independent native release build took 9m05s | Buildx GHA cache and cargo-chef dependency layers; run the exact loaded image ID with revision validation |
| QEMU infrastructure | Issues #437/#438 came from one Docker Hub timeout before guest execution | Bounded transient-only digest-pinned controller pulls; retain failure logs; no product-test retries |
| Artifact transport | Already-compressed QEMU archives were compressed again | Upload staged tar.gz archives with compression level zero |
| Failure reporting | One detailed QEMU failure also produced a misleading aggregate issue | Preserve detailed failures; use aggregate only when needed; preserve authoritative main closure behavior |
| Dependency audit | Four cargo-deny graph/check invocations | One invocation with all four policies, diagnostics and failure propagation preserved |
| Scheduled load | Audit, benchmark and mutation started at the same time | Stagger schedules away from the top of the hour |
| Mutation baseline | Run 35484109922 failed before testing any of 217 candidate mutants | Assert the backend-free init contract; validate full portable baseline for relevant PR changes; preserve full mutation score gate |
| Inventory fixtures | Missing-input cases inherited an earlier env-capture lockfile | Include the independently validated fixture isolation fix from #436 |

Docker native package freshness is a deliberate cache tradeoff: UTC date changes
invalidate native layers, nightly runs rebuild without cache, and manual
`cold_cache` requests force a fresh build. Ordinary same-day PRs may reuse that
day's package snapshot. Cold builds include the pinned cargo-chef tool installation;
measure its overhead as well as warm build savings. These are still native Arch
builds, with the existing pinned base, compiler, release profile and features.

Mutation baseline mode is explicitly different from a mutation score: successful
baseline tests do not establish that mutants are caught. The scheduled/full mode
still rejects infrastructure/baseline errors and requires at least 75% caught.

## Whole-pipeline disposition

Reviewed CI, coverage, Docker E2E, QEMU matrix/lane/report/maintenance, release,
release smoke, benchmark, mutation, fuzz, CodeQL, audit, secrets and changelog.

- Retain all six native CI release builds and four staged QEMU builds for now.
  They are candidates for shared producers, not proven interchangeable artifacts:
  QEMU container releases use x86-64-v2; profiles, native libraries, test process
  models and feature combinations differ. Ubuntu is the first feasible candidate.
  A shared producer must provide both binaries, exact source/recipe identity,
  checksums and equivalent test ownership without polling a runner for artifacts.
- Retain exact-commit release prerequisites, immutable tags, release signer/source
  identity and published-artifact smoke checks. Event-driven readiness and artifact
  promotion require a coordinated producer design; deleting current gates would
  improve apparent speed while weakening evidence.
- Retain privileged Arch sandbox checks. They currently wait for the full matrix;
  an independent Arch producer can shorten that dependency in the shared-build
  design, while the aggregate must still require every platform.
- CodeQL already uses no-build analysis. Keep both Rust and workflow analysis.
  Keep both secret scanners; neither is a significant measured bottleneck.
- Keep the pinned fuzz toolchain, corpus persistence and offline locked campaign.
  Keep mutation coverage and its score threshold. Do not reduce runtime coverage
  to reduce minutes.
- Preserve release LTO/linker settings, distro-native behavior and current retries
  pending targeted performance/flakiness evidence. Compiler/linker experiments
  need size, runtime, unwind and security regression measurements.
- Do not bulk-approve Dependency Dashboard updates as an optimization. Tool pins
  and Renovate cadence need maintenance with compatibility checks.

These items remain explicit limits: this PR is not evidence that every possible
optimization is exhausted. Compare the final run with the baseline by workflow,
job and step; separate cold-cache, warm-cache and queue time. Do not repeatedly
rerun the full matrix simply to manufacture measurements.

## QEMU coverage findings for the next phase

At audit time `tests/cli_behavior_inventory.tsv` has 186 rows: 14 declarations,
17 help-only cases and 26 controlled-error cases. 180 rows have no custom
assertion. Those counts describe inventory entries, not unique commands or
globally missing tests.

`coverage.yml` runs the complete Arch integration suite unprivileged. QEMU also
checks actual package installation/removal, native version agreement and daemon
behavior. Existing exact inventory hashes, case reconciliation, approved-skip
policy and transport-versus-product failure distinctions must remain.

| Gap | Why current green results are insufficient | Required evidence |
| --- | --- | --- |
| Long flag inventory | Declaration rows count as coverage but QEMU skips them | Map every option to parser, refusal and successful behavioral tests |
| Command inventory | Help output can satisfy command coverage | Exercise the actual operation and inspect its result |
| Exit-code-only rows | Ignored flags or incorrect state can still exit zero | Semantic output, native package DB and before/after state assertions |
| Error-only cases | Missing snapshot/runtime/config can prevent the intended operation | Successful fixtures before rollback, restore, uninstall and authorization tests |
| Export artifacts | Nonempty file or syntactically valid JSON is too weak | Validate schema and requested record/content semantics |
| Debian/Ubuntu integration | Ordinary matrix uses lib/bins; Arch coverage cannot activate Debian-only modules | Enumerate and run relevant Debian/Ubuntu integration modules; reject zero selected tests |
| Interface partitions | Long flags alone omit aliases, short flags, defaults, values and combinations | Generate the interface inventory from Clap and map each partition to evidence |
| PTY/network/containers | Advertising a tier does not execute declaration-only cases | Deterministic PTY, local HTTP, service and nested-container fixtures |
| ARM/debian-pure | Dispatch-only ARM and lint-only debian-pure are not full runtime coverage | Explicit architecture/feature runtime lanes with supported-case accounting |

Some declaration cases already have other tests: daemon foreground runs in the
QEMU lifecycle, doctor network/EOL have targeted integration tests, and fast/turbo
have parser/refusal tests. Import that evidence before adding duplicates.

Next phase order: build the authoritative evidence map; strengthen weak assertions;
run missing platform integrations; exercise successful state changes in disposable
VMs; add PTY/network/service fixtures; then fault injection and option interactions.
Publish selected/executed/skipped counts by evidence type. A green parser or help
check must never be presented as proof that a state-changing operation works.

## Primary research sources

- [Rust direct libtest compilation](https://doc.rust-lang.org/rustc/tests/)
- [Pinned dependency-cache implementation](https://github.com/Swatinem/rust-cache/tree/6323deb102c322ba6fcbdcafc7e3dddab59af2b6)
- [Docker cache optimization](https://docs.docker.com/build/cache/optimize/)
- [BuildKit GHA cache behavior and limits](https://docs.docker.com/build/cache/backends/gha/)
- [cargo-chef dependency recipes](https://github.com/LukeMathWalker/cargo-chef)
- [cargo-deny combined policy checks](https://embarkstudios.github.io/cargo-deny/cli/check.html)
- [cargo-llvm-cov reports and instrumentation](https://github.com/taiki-e/cargo-llvm-cov)
- [cargo-mutants scratch build directories](https://mutants.rs/build-dirs.html)
- [GitHub concurrency semantics](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [Artifact compression controls](https://github.com/actions/upload-artifact)

Hosted baseline links: [Docker 35488596504](https://github.com/omg-cli/omg/actions/runs/35488596504),
[coverage 35488596487](https://github.com/omg-cli/omg/actions/runs/35488596487),
[mutation 35484109922](https://github.com/omg-cli/omg/actions/runs/35484109922).

## Verification before the consolidated push

All 16 workflows pass actionlint 1.7.12. Local suites ran 144 tests with 13
Linux-only skips: CI/policy 37, Docker workflow behavior 7, maintenance 2, QEMU
helpers 69, QEMU workflow 18, exporter 11. Diff whitespace checks pass.
An independent whole-PR review found no blocking source-level defects.

Review boundaries: Windows cannot establish native Rust/Docker/KVM success;
hosted checks remain mandatory. Cache savings remain unmeasured on the final
revision. The deliberate daily Docker freshness policy is documented above;
rolling package upgrades in other existing native jobs remain unchanged.
Broader CLI behavioral coverage is the next phase, not claimed complete here.

## Hosted evidence on d752a841

CI, security audit, release smoke, benchmark and all four x86-64 QEMU guest
lanes passed. Coverage ran 2,835 tests: 2,834 passed, one bootstrap policy test
incorrectly rejected a local Docker stage as an unpinned external image.
The portable mutation baseline exposed inherited runner NVM state in task
fixtures. Both failures remain blocking until their repairs pass hosted checks.

Docker job attempt 1 took 14m17s cold, including 13m27s image build/cache export;
attempt 2 on the same revision took 2m08s, including 79s for image build/reuse.
All ten Docker tests passed on both attempts. This establishes same-revision
warm reuse only, not source-change or long-term cache performance. Cold cache
export has a measurable cost; retaining this optimization requires that reuse
continues to offset it over real subsequent builds.

On 47d4295d, a changed build context completed Docker in 6m54s (image step
6m20s), with the test driver still compiling in one second. This is a more
representative incremental sample than the same-revision rerun, although the
production Rust source itself did not change. The NVM fixture regression passed;
the portable baseline then exposed seven team tests assuming a package backend.
Their native success contracts are retained; portable builds receive explicit
unsupported-operation and unchanged-state contracts. Future baseline runs use
`--no-fail-fast` to collect all failing integration binaries in one run.


## Baseline repair evidence on fc233d04

All four x86-64 QEMU lanes, instrumented coverage and Docker passed. Docker
completed in 6m53s after a production Rust source change (image step 6m17s,
std-only test-driver compilation one second). Coverage took 10m31s. These are
individual observed runs, not a statistical performance guarantee.

The complete portable baseline now passes the environment/backend refusal,
metrics isolation and unscanned-status repairs, but still fails two package-info
cases. The mock package/backend pair selected the Arch-specific path in a build
without that path. The next repair pairs distro and package explicitly and uses
the generic mock adapter for portable builds. Baseline failures now retain
compiled dependency caches; workspace crates retain the action's default pruning.
The baseline must pass before parser/contract inventory implementation begins.

QEMU reporting now retains all admitted failure identities in a source/attempt-bound
catalog even when more than 25 cases fail. The issue-write cap is preserved with
an aggregate issue linked to a 30-day reporter artifact. Duplicate JSON keys and
case/distro mismatches are rejected. Local reporter tests cover API failures,
invalid artifacts and cancellations without posting synthetic issues.

## Portable baseline on 2ad77381

[The complete portable baseline](https://github.com/omg-cli/omg/actions/runs/35498224871)
passed 1,951 tests, with 39 ignored. Its 85 result groups include 40 with no
passing tests; cfg-disabled targets and ignored cases are not executed coverage.
The package-info fixtures now select a mock backend supported by their compiled
feature set. Native success assertions remain in place.

Instrumented coverage on the preceding revision discovered a generated query
`-V` selecting the real version flag. Generated literal queries now insert `--`
only when needed, retaining the ordinary search fast path. The counterexample
seed is saved, and a dedicated regression distinguishes literal queries from
help/version flags. Property-test retries are disabled so a later random sample
cannot conceal the first failure. Hosted coverage on 2ad77381 passed 2,840 tests
with 43 skipped; native CI and all four selected QEMU distro lanes also passed.

The trusted QEMU reporter now includes bounded per-case diagnostic excerpts,
scrubbed before truncation, alongside source/run/attempt identities and the full
failure catalog. Fake API tests verify reporting without creating artificial
issues. The existing live lifecycle is demonstrated by issue #438, which recorded
a scheduled failure and closed after verified main-run success; that historical
event does not validate these newer, unmerged reporter changes.

Successful jobs were not sufficient proof of caching. Inspecting 2ad77381 logs
found five native/intersection cache restores rejected because their feature
strings contained commas. The cache action reported success despite the validation
error and never saved those caches. The repair hashes the NUL-separated platform,
image and feature tuple; regression tests execute the workflow's key calculation
and verify compatibility boundaries and valid bounded keys. Hosted save/restore
verification remains required.

The cache API reported 11,309,166,975 bytes across 28 entries at audit time;
coverage had a cache miss. Cache eviction pressure is a separate measured risk,
not proof that every miss was eviction. No paid storage setting was changed.
[GitHub's cache reference](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
documents the default 10 GB limit and eviction behavior;
[the toolkit implementation](https://github.com/actions/toolkit/blob/main/packages/cache/src/cache.ts)
enforces the comma and 512-character key restrictions.

## Expanded-suite baseline and producer reuse

All nine workflows pass on `00ce6237`, including [CI](https://github.com/omg-cli/omg/actions/runs/35504747019)
and [QEMU](https://github.com/omg-cli/omg/actions/runs/35504747101).
Selecting the previously omitted Debian suites exposed stale oracles and two
fixture defects: root-run mock commands shared production state paths, and plain
status bypassed the fixture used by JSON status. Both are repaired without
changing production root path protections. Assertions now pin package/update
counts, exact installed versions and unchanged package state after refusal.
Pure Debian reports 1,462 executed/passing tests, 32 skipped and zero retries;
those execution counts are not a behavioral coverage percentage.

The QEMU sample before producer reuse used these elapsed job seconds:

| Distro | Staged build | Guest |
| --- | ---: | ---: |
| Arch | 408 | 335 |
| Debian | 343 | 330 |
| Fedora | 326 | 395 |
| Ubuntu | 258 | 441 |

The eight jobs consumed 47.27 runner-minutes, excluding preparation/aggregation.
On the same revision, native CI's release steps completed between 10:24:30 and
10:27:47 UTC. Four separately waiting consumers could therefore spend roughly
25 runner-minutes waiting, exceeding the 22.25 minutes used by staged builds.
This is an estimate from timestamps, not a measured reuse run or a billing claim.

The revised reuse design has one preparation job wait for artifact availability.
Guests then independently check the API run/attempt, exact recipe, server digest,
archive digest and both binaries. CI tests remain mandatory. Manual staged builds
retain their serial tests; automatic runs move those tests to the native owner.
The shared readiness barrier can delay an individual guest, so the next hosted
run must measure both total runner time and whole-gate latency. No speedup is
claimed until that comparison exists. Readiness logs and admission-failure
diagnostics remain available alongside the trusted QEMU issue-reporting path.

### Native artifact reuse checkpoint 5116471f

QEMU run 35505933279 passed all four guests using early native CI artifacts.
Each guest independently passed source/recipe/run/attempt and archive/binary digest
admission in 2–4 seconds; all duplicate staged-build jobs were skipped.
Including preparation and aggregation, observed QEMU runner time was 31m35s
versus 47m42s on 00ce6237 (about 34% lower). Guest durations were Arch 321s,
Debian 325s, Fedora 352s and Ubuntu 425s; preparation consumed 466s.
Workflow completion took 15m02s versus 12m56s: the shared artifact barrier traded
about two minutes of latency for fewer runner minutes. These are individual
observations, not whole-CI savings or guaranteed improvements.

CI 35505933163 exposed a Trixie workflow regression: its container defaulted to
sh, so the new Bash conditional selected the wrong branch. Other native owners
passed. The follow-up explicitly selects Bash and extends the recipe regression
test to verify that selection. It also preserves independent guest diagnosis
when a sibling producer has no artifact: readiness logs absence under one shared
deadline, while each guest still performs mandatory admission and retains its
lifecycle failure evidence. Invalid identities remain blocking. The focused
65-test suite and actionlint passed; a new hosted checkpoint is still required.

### Behavioral evidence import (prepared after 56cc1bf1)

Three contracts now map reviewed exact assertions in two Debian CLI fixtures:
human status, JSON status and explicit install consent. Their separate adapter
binds the actual debug child executable and owning test harness before/after the
single existing nextest run, rejects skips/unreviewed mappings, and preserves
failed attempts. The fixtures assert private state cleanup; a subprocess negative
control rejects a test harness substituted for the product executable. This is
mock-backend CLI evidence, not native transaction or daemon coverage. The broader
inventory remains explicitly incomplete. Local adapter/selection tests pass;
the new Rust assertions and generated receipts require hosted execution.

The completed 5116471f coverage run 35505933179 retained LCOV with 53,911 of
70,574 reported source lines hit (76.4%) and 5,817 of 7,593 functions hit.
This is the arch,pgp,license instrumented build, including compiled in-source
test code; disabled features and other platforms are not represented. LCOV
reported BRF=0 and BRH=0, so branch coverage is unavailable, not 100%.
These instrumentation totals must not substitute for behavioral contract counts.

Checkpoint 56cc1bf1 subsequently passed all nine workflows, including CI
35516409756 and QEMU 35516409883 with all four guests. The shell correction and
native artifact reuse therefore have hosted confirmation before the behavioral
receipt batch is published. Final independent review and the remaining semantic,
daemon, native fault and interaction work are still pending.

### Daemon transport regression batch

The three CLI fixture contracts passed on Debian, Trixie, Ubuntu and pure Debian
in CI 35517223784. The pure owner retained 1,463 passed executions, 32 skipped,
zero failed and zero retried; skips are not covered contracts.

The next daemon batch retains and joins the production server task, checks IPC
readiness, exercises SIGTERM draining and explicitly removes its fixture state.
It adds fragmented/coalesced frames, partial-frame disconnect recovery, bounded
response allocation and truncated-response rejection. The active-connection
oracle waits for explicit counts instead of sampling a potentially unsettled
baseline after a fixed delay. An exhaustive request match and witnesses generated
from one test macro bind all 15 compiled Request variants to the reviewed manifest.
This is inventory/codec evidence, not successful handler coverage.

A new custom-socket regression requires the fast-status file beside that socket.
Static inspection shows public server::run currently derives the path globally;
the hosted regression is expected to expose this before a production repair.
Rustfmt and TOML parsing pass locally; this Windows host cannot execute the Linux
server tests. The batch's Rust outcomes remain pending. Automatic QEMU failure
issue reporting is unchanged, and no synthetic production issue is created.

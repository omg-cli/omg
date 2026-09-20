# Consolidated CI/CD audit and QEMU verification roadmap

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

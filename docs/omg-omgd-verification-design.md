# OMG and OMGD verification design

Status: user-approved design (2026-09-20), not a claim of implemented coverage.
CI optimization PR #440 must pass its final revision. Its initial portable baseline
found inherited NVM state leaking into hermetic fixtures; that fixture repair was
kept separate from subsequent production alias defects demonstrated by regressions.

## Meaning of complete coverage

Every supported public and hidden interface and every maintained feature must have
an explicit behavioral contract, executable evidence, a platform/feature owner,
and a CI gate. New or changed surfaces without that mapping fail the coverage gate.
Parser acceptance, help text, expected refusal, successful behavior, state changes,
and fault recovery are separate evidence categories. A test name or an exit code
alone cannot establish the stronger categories.

This is complete coverage of a reviewed contract inventory, not a mathematical
guarantee over every possible input, interleaving, dependency or machine. Boundaries
and constraints must be explicit. Unsupported behavior must have refusal tests;
unimplemented tests remain visible debt and cannot be counted as success.

## Research method and decisions

Exa research used fifty-nine searches (238 requested result slots),
covering CLI reflection, daemon timing/concurrency, VM testing, test selection and
mutation, process isolation, state machines, combinatorial interactions and VM
fault injection, NVM alias layout, Docker stage inheritance and issue evidence.
Additional implementation searches check concrete Clap reflection APIs and LLVM
coverage interpretation and a local Python execution failure. Results overlap;
these are not distinct verified authorities. The Python search results do not
establish the cause of the observed local failure.
Selected primary sources were read and checked against repository code.

| Source | Application here | Limit |
| --- | --- | --- |
| [Clap Command reflection](https://docs.rs/clap/latest/clap/struct.Command.html) and [grammar](https://docs.rs/clap/latest/clap/_concepts/index.html) | Generate the interface inventory from compiled Clap definitions, including subcommands, arguments and aliases | Parsing is not proof that an operation has the intended effect |
| [Rust child environments](https://doc.rust-lang.org/std/process/struct.Command.html) | Override fixture paths on each child; preserve explicit test overrides | Do not mutate shared process environment in parallel tests |
| [Rust test isolation](https://doc.rust-lang.org/book/ch11-02-running-tests.html) | Root-run debug mock adapters must use private fixture state; assert a separate child sees an empty inventory | Production root path protections remain in force |
| [APT sources](https://manpages.debian.org/bookworm/apt/sources.list.5) | Preserve commented repository metadata with enabled=false and distinguish enabled acquisition entries | Retaining disabled configuration is not permission to fetch it |
| [NVM alias layout](https://github.com/nvm-sh/nvm/blob/master/README.md) | Test real LTS alias directories independently of isolated task fixtures | Fixture isolation does not establish production NVM compatibility |
| [NVM recursive alias resolver](https://github.com/nvm-sh/nvm/blob/f695512c/nvm.sh) and [cycle tests](https://github.com/nvm-sh/nvm/blob/f695512c/test/fast/Aliases/circular/nvm_resolve_local_alias) | Add offline chained-alias and cycle regressions before changing runtime resolution | Reading a single alias file is not recursive resolution; proposed upstream patches are not evidence of merged behavior |
| [Tempfile directory permissions](https://docs.rs/tempfile/latest/tempfile/struct.Builder.html#method.permissions) | Create daemon fixture directories explicitly with mode 0700 and validate before binding | TempDir defaults to 0777 filtered by umask; a default temporary directory is not necessarily private |
| [Proptest shrinking budgets](https://docs.rs/proptest/latest/proptest/test_runner/struct.Config.html#structfield.max_shrink_time) | Bound counterexample minimization separately from generated-case execution when strengthening slow subprocess properties | A shrinking budget does not interrupt a running case; preserve seeds, failure persistence and the original failure |
| [BuildKit GHA exporter](https://github.com/moby/buildkit/blob/master/cache/remotecache/gha/gha.go) | Do not assume registry-export compression options also apply to GitHub Actions caches | The inspected exporter uses its default compression configuration; unsupported flags are not a measured optimization |
| [Zstandard environment controls](https://github.com/facebook/zstd/blob/dev/programs/zstd.1.md#environment-variables) and [Actions cache tar commands](https://github.com/actions/toolkit/blob/main/packages/cache/src/internal/tar.ts) | Trial level 6 for newly saved Rust cache archives without invalidating warm keys or changing compiler settings | Higher compression costs CPU; retain only with measured archive-size/save-time evidence and subsequent successful restores |
| [Docker stage inheritance](https://docs.docker.com/build/building/multi-stage/) | Validate external image digests and local stage references separately | Unknown stage references still require an external digest |
| [Docker GHA cache](https://docs.docker.com/build/cache/backends/gha/) and [cache management](https://docs.docker.com/build/ci/github-actions/cache/) | Investigate dependency-stage exports to reduce pressure from source-dependent compilation layers | Keep the current max export until measurements justify the storage versus identical-revision rebuild tradeoff; min alone would discard useful intermediate dependencies |
| [Pinned tool installation](https://github.com/taiki-e/install-action#usage) | Preserve the pinned installer commit, which also pins unspecified tool versions | An omitted explicit tool version is not automatically a floating dependency with this action |
| [NIST combinatorial test generation and expected outputs](https://csrc.nist.gov/csrc/media/projects/automated-combinatorial-testing-for-software/documents/auto-test--tutorial.pdf) | Strengthen expected-output checks before adding flag combinations to QEMU; input selection and its behavioral oracle are distinct obligations | Pairwise coverage cannot certify higher-order interactions or compensate for incorrect expected results |
| [Git hook requirements](https://git-scm.com/docs/githooks) | Assert installed hooks are executable regular scripts and removed hooks are absent; isolate global/system Git configuration in guest fixtures | Default-directory fixtures do not cover core.hooksPath, linked worktrees, user-edited hooks, or execution semantics |
| [which 8.0.5 source archive](https://static.crates.io/crates/which/which-8.0.5.crate) | Check the selected executable path rather than accepting an existing NVM bin directory; inspected finder/checker source after verifying the Cargo.lock SHA-256 | One Exa query returned no results and versioned docs were unavailable; the locked source confirms absolute-path checks without execution, not binary identity or successful startup |
| [Tokio barrier](https://docs.rs/tokio/latest/tokio/sync/struct.Barrier.html) | Require both workspace tasks to rendezvous before either emits a success marker | The process fixture uses bounded filesystem signals, not Tokio itself; demonstrates overlap of these two tasks, not throughput or all dependency schedules |
| [setpriv manual](https://man7.org/linux/man-pages/man1/setpriv.1.html), [capabilities manual](https://man7.org/linux/man-pages/man7/capabilities.7.html) | Drop bounding, inheritable and ambient capabilities alongside no-new-privileges, including UID 0 | Local Arch WSL exposed the retained-capability failure; tests now inspect all five capability sets under caller and root identities |
| [GitHub artifact retention](https://docs.github.com/en/actions/tutorials/store-and-share-data) and [token permissions](https://github.com/github/docs/blob/main/content/actions/tutorials/authenticate-with-github_token.md) | Preserve actionable failure summaries in issues and link bounded artifacts; keep issue writes in the trusted reporter | Artifacts expire and PR execution must not receive issue-write credentials |
| [GitHub job prerequisites](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs) | One readiness coordinator avoids four idle artifact consumers; each guest still validates the exact binary pair | A shared barrier can increase an individual guest's latency; measure runner time and whole-gate latency separately |
| [GitHub container shells](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container) | Declare Bash explicitly for the native build recipe's Bash conditionals | Tests executing a recipe in Bash must also check the workflow selects that shell; container defaults use sh |
| [Pinned Rust cache key implementation](https://github.com/Swatinem/rust-cache/blob/6323deb102c322ba6fcbdcafc7e3dddab59af2b6/src/config.ts) | Preserve compiler/environment/manifest hashes while recovering the macOS cache namespace and excluding cached helper binaries | A restore miss plus reservation failure does not by itself prove eviction, a concurrent writer or a service defect; verify a later restore |
| [GitHub cache limits and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching) | Measure cache occupancy and verify both saving and subsequent restoration | Near-limit occupancy is not proof of eviction; do not change paid storage settings as a speculative fix |
| [Cargo feature ownership](https://doc.rust-lang.org/stable/cargo/reference/features.html) | Keep supported success tests on their backend lanes; test explicit portable refusal separately | A cfg-disabled test contributes no behavioral coverage on that build |
| [Cargo test targets](https://doc.rust-lang.org/cargo/reference/cargo-targets.html) | Verify actual test execution under each feature recipe; enable mock-backed Unix daemon transport tests outside Arch | Fedora reproduced a zero-test success before removing the unnecessary Arch gate; this expands transport coverage, not native backend transaction coverage |
| [Nextest JUnit](https://nexte.st/docs/machine-readable/junit/) | Preserve successful output or explicit receipts for runtime skips | Default success-output and skipped-test reporting can hide early returns; check installed version |
| [Nextest binary lists](https://nexte.st/docs/machine-readable/list/) and [executable environment](https://nexte.st/docs/configuration/env-vars/) | Bind CLI fixture receipts to the owning package's non-test executables and check the child helper's actual compiled path | A parser harness digest cannot identify a CLI subprocess; mock backend assertions do not certify native transactions |
| [Tokio task ownership](https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html) and [Unix signals](https://docs.rs/tokio/latest/tokio/signal/unix/struct.Signal.html) | Retain the real-server task, establish readiness through IPC and join its SIGTERM drain before fixture cleanup | Dropping a handle detaches it; abort does not prove graceful shutdown. Signal listeners affect the whole test process, so server tests remain serial |
| [Proptest timeouts](https://proptest-rs.github.io/proptest/proptest/forking.html) | Bound generated tests and replace accidental public-network parsing checks with deterministic fixtures | Forking and timeout settings do not create a behavioral oracle |
| [Mutation timeouts](https://mutants.rs/timeouts.html) | Measure the unmutated owner suite before selecting mutation deadlines | The current 60-second deadline is shorter than some existing unmutated integration tests |
| [GitHub privileged workflows](https://docs.github.com/en/actions/reference/security/secure-use) | Preserve overflow failure identities in trusted generated artifacts; keep PR artifacts away from issue-write execution | Only allowlisted data is admitted; requested artifact retention remains subject to repository limits |
| [LLVM coverage export](https://llvm.org/docs/CommandGuide/llvm-cov.html) | Interpret LCOV line/branch data separately from contract adequacy | No exported branches does not mean branches are fully tested |
| [Tokio testing](https://tokio.rs/tokio/topics/testing) | Controlled time for isolated async deadline tests; scripted AsyncRead/AsyncWrite failures | Paused Tokio time does not control kernel sockets or external processes |
| [Tokio shutdown](https://tokio.rs/tokio/topics/shutdown) | Verify signal detection, cancellation propagation and bounded draining separately and together | A signal-delivery test alone does not prove resources were released |
| [Loom](https://docs.rs/loom/latest/loom/) | Model small synchronization/atomic ownership components where production types can be instrumented | It is not an automatic model checker for the whole Tokio daemon |
| [Proptest state machines](https://proptest-rs.github.io/proptest/proptest/state-machine.html) | Generate/shrink sequences such as install-update-remove and start-connect-refresh-stop; save failing seeds | A model must be independent of the implementation, not duplicate its mistakes |
| [Nextest selection](https://nexte.st/docs/selecting/) | Compare discovered, selected, executed, ignored and skipped tests for each feature lane | A successful zero-test feature-gated binary proves nothing |
| [Mutation testing](https://mutants.rs/) and [nextest integration](https://mutants.rs/nextest.html) | Check whether assertions catch wrong behavior; retain baseline failure as fatal | Nextest and libtest have different isolation; nextest omits doctests |
| [NIST interaction testing](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software) | Constrained pairwise coverage plus higher-order security/transaction cases | Pairwise is not exhaustive; order and state transitions also matter |
| [QEMU block fault injection](https://www.qemu.org/docs/master/devel/testing/blkdebug.html) | Selected disposable-VM disk faults with observable recovery assertions | Guest filesystem ENOSPC is not identical to a host backing-image error; test both where relevant |

QEMU qtest documentation concerns testing the emulator/device models. It must not
be cited as evidence that applications inside our guests are covered. For OMG,
the authoritative assertions inspect the guest's native package database,
filesystem, process tree, sockets and command outputs.

## Audit-start evidence and gaps

The CLI TSV contains 186 rows: 14 declaration-only, 17 help-only, 26 controlled
errors, and 180 without custom assertions. These categories overlap and are not
counts of globally untested features. At audit start, `coverage.yml` ran the
complete Arch integration suite while ordinary native CI chiefly selected
lib/bins. The implementation plan tracks the added native suite ownership and
execution accounting; those changes do not erase the behavioral gaps below.

The long-flag completeness check in `tests/cli_comprehensive.rs` accepts a flag
mentioned in a declaration. The command check accepts help-only invocations.
`scripts/qemu-inventory.sh` skips declarations and mostly checks exit status;
artifact assertions check nonempty files. Successful install/remove lifecycle
tests elsewhere provide stronger native state evidence. Preserve them.

OMGD is not entirely untested: `tests/coverage_18.rs` drives real `server::run`
through malformed/versioned frames, oversized frames, rate limiting and active
connection metrics. `tests/coverage_8.rs` tests real client framing, request IDs,
wrong response variants, disconnects, retries and timeout behavior against peers.
`tests/daemon_e2e_ipc.rs` instead hosts a simplified handler loop, so that file
alone cannot prove production server timeout, framing or connection-cap behavior.
Its permissive malformed-response expectations must not substitute for the exact
contracts in coverage_18.

Key gaps to map and then close: successful semantics for declaration/help/refusal
rows; Debian/Ubuntu integration selection; debian-pure runtime behavior; aliases,
short flags, default/valid/invalid values and option interactions; production
daemon partial frames, backpressure, connection-cap recovery and shutdown during
in-flight operations; supported ARM execution; release-vs-debug behavior.

The LCOV artifact from coverage run 35493540276 at d752a841 reports 53,807/70,514
source-file lines hit (76.31%), CLI modules 14,791/21,316 (69.39%), and daemon
modules plus `src/bin/omgd.rs` 2,929/3,427 (85.47%). It contains zero branch
records. This is an Arch-feature snapshot from a run with one failing bootstrap
policy assertion; it is not final passing evidence, all-platform coverage, or
the percentage of behaviors tested. Source-file totals can include inline unit
test code and exclude feature-disabled files. Preserve these limitations.

`tests/common/mod.rs::report_skip` only prints `[omg-skip]` and callers can return
success. Neither ci.yml nor coverage.yml sets the system/network opt-ins, so
runner PASS totals can include runtime-skipped cases. Evidence admission must
distinguish those from executed assertions; required contracts need a suitable
native/VM owner, not a blanket enabling of destructive tests on shared runners.

## Authoritative inventories

Use a versioned machine-readable contract manifest, not another independent list
of hand-maintained command spellings. Generate the CLI surface from the compiled
Clap tree for each supported feature set. Generate OMGD's argument surface from its
own parser; do not infer it from `omg daemon`. Include hidden commands, implicit
help/version, aliases, short options, positionals, arity, default values, legal
enum values, conflicts, dependencies and repeated-option semantics.

Represent non-Clap behavior explicitly: environment variables, configuration keys,
IPC requests/responses and protocol version, service units, shell integration,
installer/release artifacts, stored schemas and optional features. Review source
module additions against this inventory so features without a command are covered.

Each contract record needs:

- Stable ID, source owner, supported platforms/features and input partitions.
- Required evidence kinds: parser/help/refusal/success/state/fault/concurrency.
- Preconditions and fixture construction; observable expected results and forbidden
  side effects; cleanup and timeout contract.
- Exact test IDs and owner lanes, fixture/artifact versions, bounded resource needs.
- Explicit gaps or unsupported cases with rationale; no empty mapping counted green.

Each execution receipt needs source SHA, binary digest, build recipe/features,
platform/architecture, contract and test IDs, seed if generated, attempt number,
result, duration, assertions performed, and evidence locations. Refuse duplicate,
unknown, stale, incomplete or mismatched receipts. Preserve existing QEMU inventory
hash, exact case reconciliation and harness/product failure distinctions.

## Product scope and required observations

| Domain | Interfaces/features to enumerate | Behavioral assertions |
| --- | --- | --- |
| Package queries | search/info/why/outdated/size/blame/diff/explicit/status, limits and filters | Exact fixture records, ordering, filtering, counts and output schema; CLI/daemon/native DB agreement |
| Package mutations | install/remove/update/sync/clean, dry-run/check/fast/turbo/recursive/orphan paths, review decisions | Native DB and files before/after, dependencies, locks, transaction history; dry-run leaves state unchanged |
| AUR and verification | resolution/build/review, signatures, archive inspection, paired builds, sandbox cancellation | Valid artifact acceptance; invalid/untrusted refusal; no escape, leaked workers or privileged side effects |
| Snapshots/history | create/list/restore/delete/rollback and transaction filters | Successful initial state, restoration of actual state, failed rollback preserves recoverable evidence |
| Runtime management | install/use/list/which, version pins/aliases, migration, runtime deletion | Selected executable/version, project/home precedence, safe archive/install layout, reversible changes |
| Tasks/projects/tools | run/new/tool/workspace/container and manager-specific forwarding | Exact child argv/status/environment, generated content, lifecycle state, cleanup and interruption |
| Environment manifests | capture/check/export/plan/apply/share and portable manifests | Schema/content, drift, idempotency, platform mapping, missing/invalid inputs and offline behavior |
| Shell and terminal | hook/hooks/hook-env/complete/completions/man/init/dash/watch | Parse valid scripts, actual shell behavior, PTY interaction, prompts/EOF/signals, no ANSI in machine output |
| Config/privacy/diagnostics | config/privacy/doctor/audit/stats/metrics, precedence and telemetry | Correct effective config, atomic files, permission handling, explicit consent/redaction, exact diagnostic outcomes |
| Account/team/fleet/enterprise | all subcommands with license on/off and valid/invalid identities | Authorization and claim boundaries; successful local service fixtures; live-provider evidence separately labeled |
| Updates/distribution | self-update, installer, upgrade/downgrade, signatures/attestations | Exact verified artifact, atomic replacement, interruption recovery, permissions and preserved configuration |
| Backend features | arch/debian/debian-pure/fedora/macos plus pgp/license/docker_tests | Supported combinations, feature isolation, correct unsupported errors; zero-test selection rejected |
| Filesystem/security | paths, config/lock ownership, archive traversal, symlinks, concurrency, privileges | No unintended reads/writes/elevation; atomicity, integrity and recoverability after failure |

The table is a domain index, not the final command-by-command inventory. Completion
requires generated interface records and reviewed non-CLI records, not checking
off the table based on one representative test per family.

## OMGD contract matrix

The current wire protocol has 15 requests: Search, Info, Status, Explicit,
ExplicitCount, SecurityAudit, Ping, CacheStats, CacheClear, RefreshIndex, Metrics,
Suggest, DebianSearch, Health and ListUpdates. Each needs valid, empty/not-found,
invalid-input and backend-applicability cases, exact request-ID/response-variant
checks, and meaningful payload/state assertions through the production server.

| Area | Required scenarios |
| --- | --- |
| Startup/ownership | default/custom socket, -s/--socket, insecure/missing parents, stale socket, existing live owner, wrong file type, permissions, singleton lock, startup dependency failure |
| Transport | fragmented/coalesced frames, partial header/body, size boundaries, malformed body/version, disconnect mid-read/mid-write, invalid IDs and reused connections |
| Bounds | 128-connection cap at below/equal/above boundary, permits returned after failures, slow clients, bounded read/write/request timeouts, rate-limit recovery |
| Shutdown | SIGINT/SIGTERM, idle and busy shutdown, cancellation while a worker owns resources, deadline expiry, panic/task failure, process exit status, socket/PID/lock cleanup, restart |
| Cache/index | cold/warm queries, clear/refresh, native DB changes, stale index rejection, failed refresh retains coherent state, simultaneous query/refresh, TTL/cleanup boundaries |
| Background work | refresh/cleanup/health tick ordering, delayed work, cancellation, socket replacement/removal, worker failure propagation |
| CLI-client parity | direct backend versus daemon results, daemon unavailable fallback, cache invalidation after CLI mutation, concurrent clients with distinct IDs |
| Observability | health/status/metrics reflect actual requests/errors/connections, no leaked credentials, telemetry failures do not replace original product errors |

Use real `server::run` for wire/concurrency acceptance and the actual `omgd` binary
for process/signal/service acceptance. Mock handlers are appropriate for focused
client tests but must be labeled accordingly. Explore small internal synchronization
models with Loom only where instrumentation is feasible and bounded.

## Execution ownership and efficiency

1. Fast PR gate: inventory/schema completeness, policy and harness tests; parser
   contract checks reuse existing compilation owners. No new full build per flag.
2. Native Rust lanes: per-feature selected-test manifests, unit/integration/property
   tests and exact assertions; include doctests via their own existing Cargo owner.
   Keep privileged and unprivileged contracts distinct.
3. Deterministic service lanes: real daemon sockets, local HTTP fixtures, PTYs and
   container lifecycle. No production accounts or secrets needed for ordinary PRs.
4. Disposable QEMU lanes: test the exact packaged OMG/OMGD pair, offline repositories,
   native package effects, privilege boundaries, services, install/upgrade/recovery.
   Reset a snapshot per destructive scenario group; verify reset state before reuse.
5. Full scheduled/release gate: all supported distro/architecture contract groups,
   longer generated state sequences, selected higher-order interactions, fault
   injection, mutation/fuzz campaigns and published-artifact smoke checks.

Assign each assertion an owner and reuse compatible build artifacts. Where ABI,
compiler/features or release provenance differ, retain distinct producers. A broad
test suite must not recreate the duplicate-build problem the CI audit is addressing.

Fast PR selection is permissible only with a reviewed dependency map and a full
periodic/release run. Unknown paths or failed classification select full coverage.
Feature inventory additions always demand a mapping, even when the ordinary PR
lane cannot execute that platform. Platform omissions are visible debt, not success.

## Fault and interaction strategy

For each mutating operation, identify interruption points before download, during
download, verification, extraction, staging, commit and cleanup. Test injected
network disconnect/timeout/bad response, malformed/signature-invalid metadata,
permission denial, stale lock, disk exhaustion, process death and restart. Assert
both the intended error and integrity of the previous or newly committed state.

Generate constrained pairwise option combinations, then higher-order cases around
privilege + path + symlink, update mode + daemon/cache state, and offline + signature
policy + artifact source. Add sequences, not only independent inputs. Persist and
replay minimized property/fuzz failures. Mutate assertion-critical branches to
prove tests detect wrong results instead of merely reaching code.

## Acceptance gates and order of implementation

Automatic QEMU failure issues are a required product of the pipeline, not optional
noise to remove for speed. Preserve the existing trusted reporter, stable issue
fingerprints, recurrence comments, failure excerpts and runbook links. Expanded
contracts must retain that path. Critical evidence includes source and binary
identity, platform/features, scenario/seed, expected versus actual result, safe
reproduction instructions, cleanup state and logs/artifact links. Keep a bounded,
redacted diagnosis in the issue because linked artifacts can expire.

Prove reporting behavior with a fake GitHub API/CLI: create on a new failure,
append on recurrence, deduplicate the same run, preserve distinct failures, track
a recurrence after closure, and close only after the existing authoritative main
verification. Missing/corrupt evidence must produce a visible harness diagnosis;
API failure must fail reporting. More than the per-run issue limit must retain
all failures in a linked aggregate rather than silently discarding the excess.
Untrusted PR evidence remains available through checks/artifacts and must not
gain write credentials. Do not weaken this boundary to increase issue volume.

The user prioritizes broad detection first, then tracked remediation. Coverage
growth and newly discovered issues are reported together; raw issue count is not
an effectiveness score and a clean run is not proof that uncovered areas work.

First finish #440's combined validation and record cold/warm costs. Next generate
the inventories and import existing evidence. Then fail on uncovered new interfaces
and expose the existing gap backlog without silently grandfathering it as covered.
Strengthen current TSV assertions before adding duplicate cases. Enable missing
backend integration owners; add the OMGD matrix; then implement successful mutation,
PTY/service and destructive recovery scenarios in isolated fixtures.

Completion requires all supported contract records to have executed required
evidence on their named lanes; no unknown or stale receipts; no unexpected skips;
no zero-test feature lanes; first-attempt failures visible; critical correctness and
security checks first-failure blocking; valid mutation baselines and reviewed score
results; and release evidence tied to the exact packaged binaries. Any external
service or unsupported platform exception remains explicit and separately reported.

### Local Linux verification added on 2026-09-20

Arch WSL executed the 44228779 CLI behavior inventory successfully using Rust
1.95.0 and arch/pgp/license. All fourteen output-contract and both overlap-fixture
tests ran locally, including checks previously skipped on Windows. A full quick
suite exposed retained capabilities when the namespace wrapper kept UID 0. The
regression failed before explicit capability dropping and passed afterward; the
quick suite then reported 256 tests with two explicit skips. The root path is now
covered even when the CI caller is non-root. This is network isolation evidence,
not a general filesystem sandbox. Ubuntu 26.04 and Fedora 44 WSL are additional
local feedback owners; they do not replace disposable QEMU transaction/recovery
lanes or establish coverage of unexecuted scenarios.

The local hook execution regression confirmed that a child exiting 23 still made
`omg hooks run` return success. The wrapper now returns an error containing the
child status. `tests/git_hooks_contract.rs` checks an execution receipt plus success,
nonzero exit and signal termination for all three managed hook names. It is
compiled on Unix independently of backend feature flags; it does not claim that
the generated hook templates have been exercised through every Git operation.

The daemon transport suite previously compiled to zero tests without the Arch
feature. Its fixture injects `MockPackageManager` and uses Unix APIs, so its gate
now follows Unix support. Fedora and Ubuntu locally execute all 17 tests after the
change, rather than silently omitting the suite.

QEMU run 35531270230 retained an Ubuntu Python-install failure caused by GitHub's
unauthenticated API rate limit (HTTP 403, remaining quota zero). Its 175 executed
inventory rows had 174 passes and one failure; three reviewed rows were skipped.
The admission checker correctly returned 1 for valid failing evidence, but the
caller treated every nonzero status as a harness error. The caller now preserves
independent lifecycle evidence for a validated product failure while still failing
the overall run. A full harness regression reproduced the classification defect;
controls require invalid policy evidence and simultaneous harness failures to
remain harness errors. Live API availability remains an explicit dependency;
this change does not bypass the failing installation or remove its diagnosis.

### Generated hook lifecycle coverage

The Unix-wide `git_hooks_contract` target now invokes actual Git commits,
branch and file checkouts, and fast-forward merges after installing the generated
OMG hooks. Positive and negative assertions check unstaged versus staged lockfile
warnings, branch versus file checkout notices, merge versus no-op notices, and
committed/worktree lockfile contents. These supplement the existing manual-hook
success, exit-23, and signal tests. The six-test target passed locally on Arch,
Ubuntu, Fedora, and Debian using their respective feature builds. This does not
cover merge conflicts, every Git configuration, or every generated-hook branch.
Research: [Git hook invocation contracts](https://git-scm.com/docs/githooks).

### Expanded Linux execution and QEMU hook assertions

The QEMU installed-hook oracle now exercises the installed scripts directly via
an absolute `core.hooksPath` in a disposable second repository. Commit, branch
checkout, file checkout, fast-forward merge and no-op controls verify notices and
lockfile state. Replacing each script with an executable no-op reproduced three
false passes before the stronger oracle; all are rejected afterward. The full
16-test oracle suite passed on Arch, Ubuntu, Fedora and Debian WSL. Fedora needed
its missing local gawk prerequisite. The existing failure receipt/log path remains
unchanged, including automatic trusted-run issue reporting.

The broad CLI harness previously selected zero tests on non-Arch feature builds.
Backend-independent cases now compile for Linux backend owners. The pacman database
inventory, Arch package-info/install/orphan/cache fixtures retain their Arch owner;
Fedora environment capture remains explicitly unsupported by its compiled backend.
These restrictions remain coverage debt, not successful native transaction tests.
Local unprivileged results: 82 CLI tests on Arch, 77 on Ubuntu/Debian, 76 on Fedora,
plus six hook tests on each. Execution admission now requires these selected
binaries and the production daemon transport suite to be nonempty; deterministic
failures have no nextest retries.

WSL default root execution exposed fixture contamination: production root data
paths deliberately ignore caller environment overrides and use `/var/lib/omg`.
Dedicated local `omg-audit` accounts now execute the CLI fixtures. The native CI
runner drops only the CLI comprehensive test harness to nobody inside root
containers, preserving other suites' privilege model. An actual Arch root-wrapper
run passed all 82 tests; wrapper controls preserve argv, exit status and ordinary
suite identity. Root path protections are unchanged.

The newly owned non-Arch CLI tests exposed `update --check` syncing databases.
The common update lane now skips explicit sync for check, dry-run and no-sync
modes, consistent with the Arch lane. DNF query-level cache behavior is checked
separately; mocked CLI output alone cannot prove absence of backend network work.

Research: [Git core.hooksPath](https://git-scm.com/docs/git-config),
[DNF cache-only semantics](https://dnf.readthedocs.io/en/latest/command_ref.html),
[nextest target runners](https://nexte.st/docs/features/target-runners/).

Final local evidence for this batch: the license-off `debian-pure` build passed
76 CLI tests, 17 daemon transport target tests and six hook tests. Its absent
account command is now asserted as an explicit parser refusal, rather than
counting that refusal as a successful account interaction. Fedora's new DNF
cache-only regression failed before the repair; all 50 DNF backend tests passed
afterward. The actual Fedora `omg update --check` then succeeded without mock mode
as uid 1000 in a network namespace with no network interfaces configured and all
capability sets dropped, querying cached native package metadata. It listed updates
without installing them. Quick gate: 259 tests, two explicit skips. The previous
6c07cad6 hosted baseline passed all nine workflows including all four QEMU guests;
this expanded batch still requires its own hosted validation.

### Exact search-result regression

An additional native CLI fixture now checks exact official package records,
version strings, exact/prefix/word-boundary ranking, case-insensitive queries,
`search`/`s`, short limits 0/1/2/9, detailed/short-detailed flags, quiet JSON and
unchanged package-state bytes. It executes 24 combinations per selected backend.
The candidate passed on Arch, Ubuntu, Fedora and license-off Debian locally.
Temporarily disabling the production result truncation in the isolated Arch clone
made the regression fail on limit zero with three unexpected records; restoring
the production source made it pass. This is mock-backed query behavior, not AUR
filtering or native repository metadata coverage.

### Native explicit-query parity follow-up

The strengthened QEMU daemon probe passed locally on Arch, Ubuntu 26.04,
Fedora 44 and Debian 13 with native backends, without mock package state.
Each run compared four CLI listing/count forms with native package-manager
output during both daemon launch modes and after shutdown, while asserting
increasing daemon request counts and zero reported failures. The receipt gate
now requires query parity. Diagnostic export preserves the expected inventory,
actual outputs and counters for failure investigation. Eight malformed-output
negative controls reject wrong names, duplicates, wrong counts and extra JSON.
Guest jq provisioning precedes this unconditional probe even when benchmarks
are disabled; hyperfine remains conditional. These checks supplement existing
transport fixtures and do not prove every native RPC or transaction contract.
The next extension repeats direct and foreground startup with SIGINT shutdown,
verifying successful process exit, socket removal and subsequent startup against
the same private state. All four native WSL backends passed. SIGINT has its own
mandatory receipt field and separately allowlisted diagnostic files. This does
not yet test shutdown during an in-flight transaction or forced-death recovery.
Adversarial receipt tests also reproduced a false-pass when multiple JSON
documents ended with a valid receipt. The host gate now admits exactly one
complete object, rejecting missing, false, mistyped or concatenated evidence.

### Runtime discovery failure contracts

Exa follow-up checked GitHub's official [rate-limit rules](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
and [HTTP failure guidance](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api).
A loopback HTTP regression now supplies a valid first release page followed by
403/429 exhausted quota, ordinary 403, HTTP 500, malformed JSON or an invalid
release-list schema. It asserts complete failure instead of a partial catalog,
correct quota classification/reset diagnostics, source context for other errors,
pagination arguments and the discovery user agent. All six cases passed with
the Arch, Debian, Ubuntu and Fedora feature builds locally. This validates the
shared production fetcher; live upstream quota and full CLI download fixtures
remain separate unresolved work.
A temporary isolated-checkout mutation returning accumulated releases after
quota exhaustion failed this regression with the partial catalog exposed.
Restoring the production source passed all 56 shared runtime-helper tests on
Arch. No production runtime behavior was changed in this follow-up.

### Evidence accuracy and hook force adequacy

The user's 95% target remains an acceptance goal, not permission to manufacture
passing cases or trim the inventory. Reporting tests never count as product
coverage. Fully evidenced surfaces exclude parser/help-only results, partial
contracts, failed cleanup and explicit gaps. The initial 866 behavioral surfaces
per licensed Linux owner still include provisional gap classifications; their
domain review must finish before any percentage can certify the goal. Current
per-lane reports cannot claim coverage for other lanes or architectures.

Four exact mock-search contracts are now bound to the CLI pair and their owning
comprehensive harness, with explicit fixture cleanup. Multi-harness admission
rejects missing owners and differing product pairs. Broader native, fault and
interaction gaps remain intact. Research used the official
[nextest machine-readable metadata](https://nexte.st/docs/machine-readable/list/).

The old QEMU force-install row accepted a product that ignored `--force`: its
prerequisite had already installed identical hooks. A failing negative control
proved the blind spot. The row now replaces those hooks with different user
content and non-executable permissions before invoking the product; the existing
content, executable and actual Git lifecycle assertions then require replacement.
All 17 QEMU output-oracle tests passed on all four WSL distros.

A separate CLI lifecycle regression verifies non-force idempotency (bytes,
inode and mode), preservation of user-owned hooks by install/uninstall, explicit
force replacement, status classification and repeated uninstall, using both
default and space-containing custom hook directories. All seven hook tests passed
on all four WSL builds. A production mutation ignoring the force flag failed the
new regression; restoring production behavior passed the full hook target.

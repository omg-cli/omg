# Contract evidence

The manifest is an incremental assertion inventory, not a coverage claim.
Parser tests establish grammar only. `gaps.json` retains missing behavioral
evidence even for interfaces with passing parser contracts.

`behavioral_progress` is a conservative per-lane evidence summary. Its
denominator is the distinct supported surfaces with behavioral requirements or
explicit behavioral gaps, including non-CLI interfaces. A surface earns credit
only if all its reviewed behavioral contracts passed and no behavioral gap
remains. Parser/help-only results, failed cleanup, missing owners and partial
assertions earn no credit. The 95% target uses integer arithmetic; displayed
rounding cannot pass it. An empty denominator is unavailable, never 100%.
The current inventory still contains provisional gap classifications. Until
`behavioral_inventory_reviewed` is explicitly true after their domain review,
the report cannot certify the target even if its displayed percentage is high.
This is not a test pass percentage, source-code coverage, or a claim about
other lanes/platforms. Broader gaps remain until reviewed evidence closes them.

Native CI invokes `scripts/run-native-contracts.py` around the existing nextest
run. It lists the exact feature selection, requires nonempty owned suites,
captures JUnit output, and hashes the actual parser test harnesses before and
after execution. It does not use a release executable's digest to describe a
different test executable. Each feature recipe has separate evidence; portable
and pure Debian evidence are captured before the next build can overwrite files.

The `cli-surfaces-*` artifacts contain, per owner:

- `omg.json` and `omgd.json`: compiled grammar and build identity.
- `execution/list.json` and `junit.xml`: discovered and observed executions.
- `execution/selection.json`: ignored, filtered, runtime-skipped and retried tests.
- `execution/recipe.json` and `provenance.json`: source, tools, arguments,
  configuration and test-harness identities. These are not signed attestations.
- `execution/receipts.json`, `required.json` and `coverage.json`: admitted parser
  assertions, first-failure history and explicit debt. Admission errors are
  preserved in `admission-error.json` and fail the owning job.

For Debian, Trixie, Ubuntu and pure Debian, `execution/behavior/` separately
records three reviewed CLI fixture contracts: status, JSON status and explicit
installation consent. The actual debug `omg`/`omgd` pair and owning integration
harness are hashed before and after execution. The child helper checks that its
compiled CLI path matches the admitted subject, reaps children and checks home
cleanup; the two mapped tests explicitly close their state directories.
The status fixture asserts exact seeded counts, unchanged state and independent
empty state. Consent asserts refusal without `--yes`, unchanged refused state,
and exact installed versions after consent. These use a mock Debian backend;
they do not certify native transactions or daemon behavior. Wider gaps remain.

Linux native-backend owners additionally bind four reviewed exact-search
contracts to the comprehensive CLI harness and the debug product pair. They
check canonical/alias records, case-insensitive ranking, limit boundaries,
machine output and unchanged mock package state, then explicitly close all
fixture directories. All owning harnesses are hashed before and after execution;
different product pairs or omitted harnesses fail admission. No AUR filtering,
native repository behavior, human detailed output or quiet-mode coverage is
inferred from these JSON fixtures, and their wider gap records remain intact.

Only explicitly reviewed mappings are translated. A generic JUnit pass
cannot automatically certify state changes, cleanup or successful transactions.
The QEMU inventory/evidence gate and trusted automatic issue reporter remain
separate and mandatory. Native receipts do not replace their native DB, process,
filesystem or recovery assertions.

QEMU inventory execution additionally checks each selected product's own output:
help must contain Usage, an expected failure must explain itself on stderr, panic
reports cannot satisfy any expected exit, and JSON output/export assertions require
exactly one valid document. Export artifacts must be regular files. The same checks
apply to replayed prerequisites, whose failures block dependent cases; a prerequisite's
diagnostic cannot satisfy the final command's error contract. Assertion diagnostics
remain in the row logs consumed by failure reporting. Fault-injection tests exercise
both the guest oracle and the full inventory runner with a local SSH substitute.
These are output-quality checks, not semantic schema, flag interaction, state-change
or recovery coverage. Those stronger contracts still require explicit assertions.

The workspace scenarios use two registered projects with distinct task markers.
Filtered execution requires the selected marker once and the excluded marker zero
times; sequential and parallel unfiltered execution require both exactly once,
without relying on output order. The parallel row runs a shared bounded rendezvous fixture: neither task can
complete without observing its peer. Serial negative controls must time out and
remove their ready signals. This proves overlap of two independent tasks, not
every dependency schedule or argument interaction. Git-hook install/force-install rows
require three regular executable scripts with the expected markers and valid shell
syntax; uninstall requires their absence. QEMU additionally runs those installed
scripts through real Git commits, branch/file checkouts and fast-forward merges in
a disposable repository, with positive and negative notice and lockfile assertions.
The separate native hook target checks the same lifecycle and manual child failure
propagation. User-modified hook preservation remains a separate contract.
Published inventory policy hashes are retained separately from
the expanded checkout inventory, so old release evidence is not reinterpreted.

Linux backend owners also execute the backend-independent CLI comprehensive
cases; Arch-specific package fixtures retain their Arch owner. All native owners
require nonempty hook and production daemon transport targets. In root Linux CI
containers, a recorded target runner drops the isolated CLI fixture harnesses to
an unprivileged identity, keeping fixture paths separate from real root state.
These additional JUnit results are execution evidence, not automatic behavioral
coverage credit in the contract manifest.

Runtime management and lockfile integrity are also explicit, nonempty native
owners on every platform. Root Linux runners drop these CLI fixture harnesses
to an unprivileged identity, and failures are not retried. The runtime suite has
five opt-in network cases: when disabled, their `[omg-skip]` output is reported
as unexecuted even though libtest itself prints `ok`. A green target does not
prove those network behaviors. Six Node/Python/Go pin scenarios now require
successful activation, exact current executable paths, executable identity and
checked fixture cleanup. A pinned Rust toolchain has the same activation checks;
a locked stable-channel selection must refuse with the concurrency error and
leave no active toolchain. These installed fixtures do not prove downloading or
extraction. Opt-in downloads now disable synthetic runtime mode, require success
and execute the installed binary with the exact resolved version. Latest/LTS
expectations come from Node's separate published TSV release table, selecting
the highest eligible stable semantic version independently of OMG's JSON
resolver. Upstream changes during execution fail visibly; there is no retry to
hide them. Download failure is never accepted as successful installation.
Eleven offline runtime fixture contracts are bound to their actual owning harness
and product pair. Their named selection/refusal/state assertions and cleanup
are admitted separately; broad runtime gaps and opt-in downloads remain outside
that credit.
The uninstall lifecycle runs every one of the 68 registered dispatches against
real temporary directories and links: active-version refusal, inactive removal,
missing/symlinked-version refusal, and preservation of sibling and external bytes.
A registry-size change requires explicit fixture review. These fixtures do not
prove concurrent filesystem race handling or successful installation of all tools.

JUnit's skipped-test reporting varies by nextest version. The independent list
supplies ignored/filtered counts even when no XML row exists. A selected test
missing from XML is an error. `[omg-skip]` in successful output is counted as
unexecuted, never passing evidence. The current generic execution report does
not prove that every legacy early-return path uses that marker; review remains
necessary before assigning a behavioral contract.

The complete portable `cargo test` baseline in `mutation.yml` is the current
doctest owner. Nextest results must never be described as including doctests.
Native destructive/network opt-ins and `docker_tests` require explicit isolated
owners; disabled cases and cfg-disabled features are outstanding coverage debt.

## Native release reuse

Automatic PR/main QEMU lanes consume an early CI upload of the matching release
`omg` and `omgd` pair. The receiver checks the GitHub workflow/run/PR/attempt,
checkout SHA, distro image, feature set, toolchain, CPU baseline, profile and
instrumentation before admitting the archive. It verifies GitHub's artifact
digest, the archive digest and both binary digests, and rejects unsafe archive
members. These records are build evidence, not signed release attestations.

The native CI gate remains mandatory even when a guest starts before CI tests
finish. The former staged-build serial libtest run moves into the corresponding
native CI owner; nextest selection and retry evidence remain separate. Manual
staged runs still build and test locally; published-release verification remains
unchanged. No coverage-instrumented binary can substitute for the release pair.

The preparation job waits once for artifact availability before allocating guest
runners. Metadata readiness does not admit binaries: each guest independently
verifies its archive and has a short deadline if the producer changes attempts.
An unavailable producer does not suppress sibling guests: readiness records that
absence and each guest enforces admission, retaining its own lifecycle failure
evidence. Invalid producer identity still blocks the coordinator. The coordinator
uses one shared deadline, including when a producer never uploads its artifact.
This adds a shared readiness barrier, so compare total runner minutes and guest
completion time on hosted runs before claiming a measured speedup.
The trusted automatic QEMU issue reporter still owns failure publication.

The unconditional native daemon probe compares `--json explicit`,
`explicit --count`, `ec`, and `--json explicit --count` against an independent
native package inventory on Arch, Debian, Ubuntu and Fedora. It checks both
direct and CLI foreground daemon startup, increasing request counters with no
reported failures, and direct CLI queries after shutdown. A mandatory
`query_parity` receipt prevents missing checks from passing admission. Exact
query outputs and daemon counters are allowlisted diagnostic artifacts. This
does not establish coverage of every RPC variant or native transaction.
The probe also sends SIGINT to both direct and foreground-launched daemon
processes, verifies successful termination and socket removal, and starts the
next lifecycle against the same private state. Admission requires `sigint: true`;
signal-specific logs and query outputs remain separate exported artifacts.

QEMU's `runtime-python-install` row requires a numeric requested version, uses
private runtime state, checks the active link and executable stay inside the
installed version, and runs that interpreter to verify its exact version.
A missing, inactive, wrong-version, broken or escaped installation fails even
when the CLI exits zero. Cleanup is checked before the row passes. This stronger
oracle also applies to reviewed published inventories with that row identity;
it does not change their recorded hashes or pretend they gained other tests.

`execution/daemon/` contains a separate `native-daemon-fixture` report for eleven
reviewed production-server contracts. Its OMGD binary hash identifies the actual
`coverage_18` integration harness containing `server::run`; it never identifies
a standalone daemon executable that these tests did not launch. The OMG hash
in this lane remains the parser harness used for compiled surface inventory;
this lane admits no OMG CLI contracts. Harness ownership and pre/post execution
hashes are checked. The same nextest run supplies the observations, so this
reconciliation does not add another test run. Injected package state, real Unix
transport, explicit SIGTERM drain and checked cleanup are the bounded scope.
Native backend, executable lifecycle, security-audit and wider request/fault
coverage remain separate gaps. Do not add percentages from separate lane reports.

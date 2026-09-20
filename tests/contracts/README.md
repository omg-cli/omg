# Contract evidence

The manifest is an incremental assertion inventory, not a coverage claim.
Parser tests establish grammar only. `gaps.json` retains missing behavioral
evidence even for interfaces with passing parser contracts.

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
syntax; uninstall requires their absence. This does not establish hook runtime
semantics or preservation of user-modified hooks. The native inventory runner uses
the same assertions. Published inventory policy hashes are retained separately from
the expanded checkout inventory, so old release evidence is not reinterpreted.

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

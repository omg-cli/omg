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

Only reviewed parser mappings are translated by this adapter. A JUnit pass
cannot automatically certify state changes, cleanup or successful transactions.
The QEMU inventory/evidence gate and trusted automatic issue reporter remain
separate and mandatory. Native receipts do not replace their native DB, process,
filesystem or recovery assertions.

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

# OMG and OMGD Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish executable evidence for every supported OMG/OMGD contract and close the resulting behavioral gaps without duplicating compatible builds.

**Architecture:** Derive CLI surfaces from the compiled parsers; keep non-CLI contracts in a reviewed manifest. Map contracts to existing native, service, QEMU and release owners and reconcile their actual execution evidence. Strengthen existing fixtures and runners before adding another abstraction.

**Tech Stack:** Rust/Clap, Cargo/nextest, Python standard library, existing shell/QEMU harness, local service fixtures, proptest and cargo-mutants.

**Spec:** `docs/omg-omgd-verification-design.md`, approved by the user on 2026-09-20.

## Global constraints

- One PR: all work remains on `codex/ci-qemu-reliability`, PR #440.
- First finish #440's combined validation and record cold/warm costs.
- Unsupported behavior must have refusal tests; unimplemented tests remain visible debt and cannot be counted as success.
- Preserve existing QEMU inventory hash, exact case reconciliation and harness/product failure distinctions.
- Critical correctness and security checks are first-failure blocking.
- Preserve automatic detailed QEMU failure issues, recurrence tracking and authoritative verified-fix closure throughout this work.
- No production accounts or secrets needed for ordinary PRs.
- Unknown paths or failed classification select full coverage.
- Keep the core minimal: test helpers stay in tests/scripts; no new production CLI introspection command.
- Supported platform/feature ownership must be established from Cargo, workflows and release assets, not inferred from a feature name alone.
- Literal all-input/all-interleaving correctness is not a measurable completion criterion. Report contract coverage, execution coverage and mutation adequacy separately.

## Review focus

1. Parser aliases, hidden arguments and feature-dependent commands can disappear from a text-derived inventory: task 2 uses compiled parser traversal and synthetic parser fixtures.
2. A passing help/refusal case can masquerade as successful functionality: task 3 rejects evidence-kind substitution.
3. Host environment and native database state can contaminate fixtures: tasks 1 and 5 assert isolation and explicit environment overrides.
4. A retry can hide the first real race or security failure: tasks 3 and 8 preserve attempts and block critical first failures.
5. A daemon test can exercise a replacement loop instead of production framing/lifecycle: task 6 owns real-server and real-process tests, with bounded teardown.

## Implementation order and evidence

Do not advance the implementation onto a broken baseline. Research the relevant primary sources through Exa before each task; record the source, the decision it supports, and limitations in the design's research ledger. A search result count is not a count of verified independent authorities. Run the narrow failing regression, make the smallest repair, then run its owning suite. Record genuine failures rather than retrying until green.

### Task 1: Restore and document the consolidated baseline

**Files:** `tests/common/mod.rs`, `tests/coverage_4.rs`, `tests/security_privilege_escalation_tests.rs`, `.github/workflows/mutation.yml`, `docs/ci-cd-consolidated-audit-2026-09-20.md`.

**Interfaces:** Existing `TestProject::run`/`run_with_env` remain unchanged. Explicit fixture overrides retain precedence over default isolated paths.

- [x] Capture hosted failures on d752a841: NVM host-state leakage in four coverage_4 cases; bootstrap assertion misclassifying local Docker stages.
- [x] Add `NVM_DIR` isolation and a subprocess regression that reexecutes the exact affected test under an external NVM alias directory and requires `1 passed`.
- [x] Recognize previously checked Docker stages while rejecting mutable external images, unknown stages and malformed digests; preserve pinned rustup/Cargo checks.
- [x] Push scoped repair 47d4295d into the same PR.
- [x] Require hosted coverage and the full portable baseline to pass. Preserve skipped-test counts in evidence; they are not covered contracts.
- [x] Record final QEMU results for all selected distros and the exact source SHA. Compare source-changing Docker reuse with the existing cold 14m17s/warm 2m08s same-revision samples.

Verification:

```sh
cargo test --locked --no-default-features --features pgp,license --test coverage_4
cargo test --locked --features arch,pgp,license --test security_privilege_escalation_tests docker_base_policy
python3 -m unittest discover -s scripts -p 'test_ci_optimization.py'
```

The Rust commands require their native Linux dependencies; Windows policy checks do not replace them. Investigate real NVM LTS-directory compatibility separately in task 5.

### Task 2: Generate complete parser surfaces without changing the product interface

**Files:** create `tests/support/cli_surface.rs`, `tests/cli_surface.rs`; modify the existing test module in `src/bin/omgd.rs`; create `tests/contracts/platforms.json`.

**Interfaces:** Test helper `surface(command: clap::Command) -> serde_json::Value` recursively returns a sorted `schema_version: 1` document. Each command has canonical path, aliases and hidden status. Each argument has ID, long/short names and aliases, positional index, global/required status, action, arity, possible values, defaults and exposed conflict/group constraints. Explicit parser-case records cover constraints Clap does not expose through stable reflection. No source-text approximation is accepted for the public surface.

- [x] Add synthetic parser tests with a hidden command, short alias, global flag, positional, default and constrained enum. Verify the exporter fails to exist before implementation.

```rust
#[test]
fn surface_includes_hidden_commands_and_short_options() {
    let command = clap::Command::new("fixture").subcommand(
        clap::Command::new("hidden").hide(true).visible_alias("h")
            .arg(clap::Arg::new("mode").short('m').long("mode")
                .value_parser(["safe", "fast"]).default_value("safe")),
    );
    let document = surface(command);
    let child = &document["commands"][0];
    assert_eq!(child["path"], "fixture hidden");
    assert_eq!(child["hidden"], true);
    assert_eq!(child["arguments"][0]["short"], "m");
    assert_eq!(child["arguments"][0]["possible_values"], serde_json::json!(["safe", "fast"]));
}
```

- [x] Implement traversal after `Command::build()`, using Clap's getters verified against the locked Clap version. Sort only after collecting canonical IDs; reject collisions instead of overwriting them.
- [x] Export `omg_lib::cli::Cli::command()` from the integration test and private `Args::command()` from OMGD's own unit-test module. Use `OMG_CONTRACT_SURFACE_OUT` only inside test code to write artifacts; normal test runs need no output directory.
- [x] Execute exporters for portable, arch, debian, debian-pure, fedora and macos supported builds. Record OS, architecture and exact feature list in each artifact. Windows must explicitly report OMGD unavailable if it is not built there.
- [x] Add parser round-trip cases for canonical/alias/short/long forms, legal boundary values, conflicting options, repeated arguments and `--` forwarding; assert exact parsed values or precise Clap error kinds.
- [x] Verify `cargo test --test cli_surface` per supported feature owner; OMGD exporter under `cargo test --bin omgd`. Compare exported surfaces rather than assuming feature sets are identical.
- [x] Commit only the exporter, fixtures and platform manifest after the owning checks pass.

### Task 3: Contract manifest, execution receipts and honest coverage admission

**Files:** create `tests/contracts/manifest.json`, `tests/contracts/gaps.json`, `scripts/check-contract-coverage.py`, `scripts/test_contract_coverage.py`; extend `scripts/check-qemu-inventory.py`, `scripts/export-qemu-evidence.py` and their current tests only through compatible fields.

**Interfaces:** `admit(manifest, surfaces, receipts, provenance, required_contracts) -> dict` either returns separate totals by evidence kind/platform or raises `ValueError`. Inputs are decoded JSON objects. Contract IDs are stable strings, not argv hashes. Receipts contain the exact run/source/binary/recipe/features/platform identity and required assertion IDs. Existing inventory admission remains mandatory.

Contract record shape:

```json
{"id":"omg.install.dry-run","source":"src/cli/args.rs","surface":"omg install --dry-run","platforms":["arch","debian","ubuntu","fedora"],"requires":["success","state"],"tests":[{"lane":"qemu","id":"install-dry-run-state","evidence":["success","state"]}]}
```

- [ ] Build minimal valid fixtures for one surface, one contract and one receipt, then test rejection of missing/duplicate/unknown contracts, help substituted for success, stale SHA/digest/recipe, feature mismatch, empty test selection and unapproved skips.
- [ ] Add a test that a failed first attempt followed by a passing retry remains a blocking critical result. A missing attempt sequence is invalid, not assumed clean.
- [ ] Implement strict bounded JSON reading using existing evidence-reader conventions; reject symlinks, oversized artifacts and duplicate JSON keys. Reconcile expected and observed sets exactly before computing percentages.
- [ ] Import existing tests by inspecting their assertions. Help, parser, refusal and success mappings are distinct. Every current unsupported or untested contract gets an explicit gap record with owner and missing evidence; none becomes success by being listed.
- [ ] Produce a machine-readable report plus a readable table: supported, required, executed, passed, failed, skipped and gaps for each platform and evidence kind. Reject a denominator of zero.
- [ ] Run `python3 -m unittest discover -s scripts -p 'test_contract_coverage.py'` and existing inventory/export suites. Mutation-probe the checker by dropping an expected receipt and changing one digest; both must fail.
- [ ] Commit the evidence machinery and the truthful initial gap inventory. Initial debt remains visible; new/unmapped interfaces are blocking immediately.

### Task 4: Give every native feature suite an execution owner

**Files:** `.github/workflows/ci.yml`, `.github/workflows/coverage.yml`, `.github/workflows/qemu-lane.yml`, `.config/nextest.toml`, `tests/contracts/platforms.json`, create `scripts/check-test-selection.py`, `scripts/test_test_selection.py`.

**Interfaces:** Per lane, retain `cargo nextest list --message-format json` output and the run's JUnit/results artifact. `check-test-selection.py` compares expected integration binaries/test IDs against discovered and executed identities. A cfg-disabled binary cannot satisfy its platform contract.

- [ ] Add fixture tests for missing Debian integration binaries, all-filtered selection, duplicated IDs, expected unsupported cases, and a legitimate nonempty selection.
- [ ] Test a nominally passing result containing `[omg-skip]`: it must not satisfy executed coverage. Preserve successful-test output or structured skip receipts so early-return skips cannot disappear from nextest/JUnit admission. Map system/network/destructive opt-ins to isolated owners explicitly.
- [ ] Run the existing Debian/debian-pure/Fedora integration files in compatible native owners, preserving the distinction between libapt-backed and pure Rust binaries. Expose environment/dependency failures; do not label them product passes.
- [ ] Reuse a producer only when toolchain, features, target ABI, profile and instrumentation match. Coverage builds are distinct from uninstrumented release guests.
- [ ] Make the critical contract group retries zero; preserve first-attempt data for other tests. Keep doctests under an explicit Cargo owner because nextest does not execute them.
- [ ] Verify selection-checker tests and actionlint, then hosted feature lanes. Unknown source paths select the full affected matrix.
- [ ] Commit feature-owner and selection changes together; no empty feature lane accepted as green.

### Task 5: Close CLI semantic gaps using existing fixtures

**Files:** `tests/cli_behavior_inventory.tsv`, `tests/cli_comprehensive.rs`, `tests/common/mod.rs`, `tests/coverage_4.rs`, `tests/e2e_runtime_management.rs`, `tests/env_lockfile_integrity.rs`, `tests/team_dashboard_tests.rs`, `tests/contracts/manifest.json`; domain-specific tests stay alongside existing tests.

**Interfaces:** Keep the current TSV runner and explicit assertion names. Add stronger assertion handlers only for a concrete mapped case. All task/HTTP/runtime fixtures use child-local environment and loopback services; native package effects belong to task 7.

- [ ] Walk every exported command/argument against the design's domain table and create named behavioral cases. Retain existing help/refusal cases but do not use them as success evidence.
- [ ] Package queries: assert exact fixture records, ordering, filtering, limits, count/schema and CLI/daemon agreement. Machine output must parse and must not contain ANSI/control diagnostics.
- [ ] Tasks/tools/workspaces/containers: assert child argv, exit status and environment; generated file content and permissions; cancellation leaves no worker. Existing npm separator tests are the forwarding baseline.
- [ ] Runtimes: test pin precedence, exact selected executable/version, aliases, NVM `alias/lts/*` directories, missing targets, cycles, malicious symlinks and explicit overrides. Preserve fail-closed unreadable/escaped-file tests. A normal alias directory must not be treated as a pin file merely because the requested alias is `lts`.
- [ ] Environments/config/privacy: assert capture/export/apply schema, drift, platform conversion, precedence, idempotency, atomic files, consent and secret redaction. Missing-file refusals are additional cases, not the whole contract.
- [ ] Account/team/fleet/enterprise: local HTTP fixtures must exercise successful authorization and invalid/expired identities with license on/off; assert server-observed requests and returned state. Label any live-provider dependency as a separate unresolved contract.
- [ ] Shell/PTY: run generated Bash/Zsh/Fish scripts in their actual shells; drive prompts, EOF, interruption and terminal resizing through a PTY. Assert selected action/state and absence of leaked subprocesses.
- [ ] Snapshots/history: verify exact captured content, successful restoration and transaction filters in fixtures, then pair with actual native state in task 7.
- [ ] For each case, first demonstrate that changing/removing its intended product behavior makes its assertion fail. Execute its named Rust integration file and update the manifest only after evidence exists.
- [ ] Commit domain groups within the same PR; no mass replacement of existing tests.

### Task 6: Test all daemon requests and production lifecycle paths

**Files:** `tests/coverage_18.rs`, `tests/coverage_8.rs`, `tests/daemon_e2e_lifecycle.rs`, `tests/daemon_e2e_concurrency.rs`, `tests/debian_daemon_tests.rs`, `tests/debian_ipc_tests.rs`, `scripts/qemu-daemon-check.sh`, `tests/contracts/manifest.json`.

**Interfaces:** Reuse `RealServerFixture`, `send_raw_frame`, `read_response` and production `server::run`. Retain a server task handle and explicit bounded shutdown in the fixture; do not silently leak tasks. Real `omgd` subprocess tests own signal/socket/lock behavior.

- [ ] Add a fragmented-frame test that writes one byte at a time, then a coalesced two-frame test on the same stream. Assert both response IDs and precise result variants; a timeout is a failure.

```rust
let payload = omg_lib::daemon::protocol::encode_frame(&Request::Ping { id: 901 })?;
let mut wire = u32::try_from(payload.len())?.to_be_bytes().to_vec();
wire.extend_from_slice(&payload);
for byte in wire { stream.write_all(&[byte]).await?; }
assert_eq!(read_response(&mut stream).await?.id, 901);
```

- [ ] Add success/refusal/state assertions for all 15 variants: Search, Info, Status, Explicit, ExplicitCount, SecurityAudit, Ping, CacheStats, CacheClear, RefreshIndex, Metrics, Suggest, DebianSearch, Health and ListUpdates. Expected package contents come from the fixture/native DB, not a second call to the same handler.
- [ ] Cover partial header/body then disconnect, exact size boundaries, malformed payload/version, repeated/crossed IDs, invalid UTF-8 at applicable text boundaries, request cancellation and read/write backpressure. Bound fixture response allocations.
- [ ] Hold 128 accepted connections, exercise the next connection, release one and prove service recovers. Poll observable metrics/barriers within a deadline rather than assuming sleep duration establishes state.
- [ ] Run real `omgd` with private socket/data paths: SIGTERM/SIGINT idle and in-flight, drain deadline, forced death/restart, occupied socket, stale lock, replaced inode, permission denial and startup failure. Assert process exit, socket/lock ownership and successful fresh restart.
- [ ] Verify cache/index refresh after native database changes, failed refresh integrity, TTL/background work, memory cleanup and CLI fallback/parity. Use paused Tokio time only for in-process timers; real kernel/subprocess tests retain wall-clock deadlines.
- [ ] Run Arch production-server suite and the corresponding supported backend suites with receipts; handler-only mocks cannot satisfy production-transport evidence.
- [ ] Commit daemon groups after their narrow suites pass. Changes to production timeouts or cancellation require a failing regression before the repair.

### Task 7: Native transactions, release binaries and destructive recovery in QEMU

**Files:** `scripts/qemu-transactions.sh`, `scripts/qemu-storage-faults.py`, `scripts/qemu-daemon-check.sh`, `scripts/benchmark-qemu.sh`, `scripts/prepare-qemu-release.py`, `scripts/export-qemu-evidence.py`, related existing `scripts/test_qemu_*.py`, `tests/contracts/manifest.json`.

**Interfaces:** Existing staged pair of OMG/OMGD plus provenance. Guest case evidence contains before/after native package DB records, filesystem hashes, exit/output, process/socket state and cleanup status. Snapshot reuse requires a verified reset baseline.

- [ ] Build deterministic local repositories with package A versions 1/2 and dependency B; test search/info/install/update/remove, recursive/orphan modes, conflict/lock refusal and dry-run. Compare `pacman -Q`, `dpkg-query` or `rpm -q` results and installed payload bytes, not only OMG's output.
- [ ] Exercise snapshots/rollback/history against those real package states. Inject a failed update and verify the documented committed or recoverable state, never an ambiguous success.
- [ ] AUR/build/signature cases use controlled source and signing fixtures: valid signatures succeed; untrusted/corrupt content fails without privilege or archive escape. Assert worker teardown on cancellation.
- [ ] Inject HTTP disconnect/timeout/bad metadata, disk-full/permission denial, process death at staging/commit/cleanup, corrupt archive/signature and daemon death. Guest ENOSPC uses a bounded guest filesystem; QEMU blkdebug EIO is a separate host-backing case.
- [ ] Test installer/self-update with exact verified staged release artifacts, interrupted replacement, upgrade/downgrade policy, preserved configuration and service restart. Assert both OMG and OMGD digests match the submitted recipe/source.
- [ ] Execute supported architecture lanes, including ARM where supported runner resources exist. An unavailable ARM execution owner remains a visible gap and prevents an all-platform coverage claim.
- [ ] Run existing harness unit tests before guest tests; then rerun affected guest groups after each product fix. Perform one full matrix at the final revision. Do not rerun successful unchanged matrices for reassurance.
- [ ] Commit each coherent recovery group in this PR with evidence links and any defect repairs.

### Task 8: Interaction adequacy, regression replay and final gate

**Files:** `tests/property_tests.rs`, `tests/property_tests_v2.rs`, existing `fuzz/` targets, `.github/workflows/mutation.yml`, `.config/nextest.toml`, contract checker and manifest, consolidated audit/design documents.

**Interfaces:** Generated cases have recorded seeds and contract IDs; minimized counterexamples become deterministic tests. Mutation results report eligible/killed/survived/unviable/timeout counts with a valid unmutated baseline.

- [ ] Generate constrained pairwise options per command, plus explicit higher-order privilege/path/symlink, update/cache/daemon and offline/signature/source combinations. Validate the generated combination set independently of the product parser.
- [ ] Add independent state-machine models for install-update-remove and daemon start-connect-refresh-stop. Compare observable state after each transition, not only at sequence end. Persist and replay failure seeds.
- [ ] Extend existing protocol/archive/manifest fuzz targets at boundaries revealed by the inventory. Bound time/resources, preserve crash artifacts and add deterministic regressions before claiming a fix.
- [ ] Mutate assertion-critical branches and verify their mapped tests detect wrong behavior. A surviving meaningful mutation creates a gap; a baseline failure invalidates the campaign. Do not inflate score by deleting tests or excluding uncovered production paths.
- [ ] Require critical first failures to block even when a retry passes. Keep infrastructure failures distinct and visible; retry only known transient infrastructure operations with bounded attempts.
- [ ] Run the final exact-revision native suites, full QEMU matrix and release evidence checks. Require every supported contract's named evidence on its owner lane, with no unknown/stale receipts, unexplained skips or zero selections.
- [ ] Update PR title/body and final report with measured timings, completed contract counts by domain/platform, line/branch coverage separately, mutation adequacy and explicit remaining external constraints. Never describe a pending/missing test as covered.
- [ ] Request whole-branch review before merge. Merge approval for #439 does not authorize merging #440.

### Task 9: Preserve and strengthen automatic issue evidence

**Files:** `scripts/report-qemu-workflow.py`, `scripts/qa-file-issue.sh`, `scripts/test_qemu_reporting.py`, `.github/workflows/qemu-report.yml`, `scripts/export-qemu-evidence.py`, existing `scripts/test-qa-file-issue.sh`.

**Interfaces:** Keep `<!-- omg-qa-fingerprint: source:distro:case -->` as the issue identity. Existing issue-write credentials remain confined to the trusted default-branch reporter. Use controlled `gh` fixtures for reporter verification; tests must not post synthetic issues to the repository.

- [ ] Add fake-CLI integration tests covering creation, recurring failure comment, same-run deduplication, separate cases, recurrence after closure, successful-main closure, non-main non-closure and issue-API failure propagation.
- [ ] Add reporter fixtures for missing/expired/corrupt evidence, exceeded issue limit, cancelled runs and new case IDs not yet present on main. Preserve an aggregate diagnosis when detailed evidence cannot be admitted.
- [ ] Preserve structured source/binary/feature/seed/expected/actual/cleanup fields through a bounded, reviewed allowlist. Never copy arbitrary environments, execute artifact contents or expose secrets. Put a safe bounded excerpt in the issue, with artifact lifetime and exact run/attempt links.
- [ ] When more than 25 cases fail, retain all canonical failure identities in the aggregate report while limiting GitHub writes. Deduplication must not collapse distinct faults into a bare exit-code report.
- [ ] Keep pull-request write-token isolation intact. PR-only failures must retain checks/artifacts; trusted dispatch/main verification drives automated issues under the existing policy.
- [ ] Run the reporter and fake-CLI lifecycle suites, then validate one real naturally failing trusted run when available. Do not intentionally break main or manufacture production issues to test the reporter.
- [ ] Include this task in every integration review: no pipeline refactor is accepted if it loses the automatic failure issue path.

## Plan self-review

The design's scope maps to tasks 2–3 (inventory/evidence), 4 (feature and platform owners), 5 (all CLI domains), 6 (OMGD), 7 (native mutation, distribution and recovery), 8 (interaction/fault adequacy and completion), and 9 (automatic issues). Task 1 is the prerequisite; task 9 is a continuing regression gate, not work postponed until after final acceptance. The five review risks have explicit owning tests. Test artifacts are observations, never an alternate source of product semantics. New production fixes remain driven by reproduced failures.

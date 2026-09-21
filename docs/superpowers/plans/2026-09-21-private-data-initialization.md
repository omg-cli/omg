# Private data initialization for usage persistence (#468)

## Problem and evidence

Main5685c29a Ubuntu QEMU runtime-python-install succeeded while usage.lock refused its group-writable parent. A fresh Node installation under unprivileged Ubuntu with umask0002 reproduced data mode0775 and no usage.json. Existing lock validation is correct; do not relax it.

Rust DirBuilder defaults to0777; recursive parents use the configured creation mode. Use explicit0700 creation rather than post-creation chmod. References: https://doc.rust-lang.org/stable/std/os/unix/fs/trait.DirBuilderExt.html and https://doc.rust-lang.org/stable/std/fs/struct.DirBuilder.html .

## Design

Keep data_dir() as a pure path resolver. Add an explicit fallible creation helper that creates missing data directories privately on Unix and retains platform defaults elsewhere. Never chmod pre-existing directories. Existing owner/no-follow/writability checks remain responsible for rejecting unsafe usage state.

Use this helper at usage and telemetry data-directory creation sites and before CLI runtime installation begins, covering telemetry enabled and disabled startup ordering. Trace other shared data-directory creators before finalizing scope: a different creator racing to create the same parent with0777 would preserve this bug. Prefer replacing direct creation at those owners over adding unconditional filesystem writes to help/parser fast paths.

## Execution gates

1. Add process-isolated fresh-start regression under umask0002. Observe the unmodified implementation produce0775 and fail persistence. Never change the parent test process umask.
2. Add helper checks for private recursive creation, idempotence, unchanged existing directories, and existing lock rejection of writable/symlink parents. Do not treat preservation of unsafe existing state as a successful usage update.
3. Implement the creation helper and update the audited owners; keep lock validation unchanged.
4. Build the CLI and reproduce real runtime use with telemetry enabled and disabled. Require exact runtime_usage_counts increment and persisted command count, not just absence of a warning. Confirm runtime execution still works.
5. Run targeted usage/telemetry/path and runtime tests on all four Linux feature owners, plus a fresh hosted QEMU row carrying the assertion before closing #468. Keep existing users with intentionally shared directories explicit; no silent permission migration.

## Implementation and validation

The path resolver remains pure. Explicit private creation now covers runtime selection, usage persistence, telemetry queue/session/install markers, and license/machine-id/clock writers. Existing directories are neither chmodded nor exempted from the usage lock checks. The QEMU runtime rows use umask0002 and require one persisted runtime switch, the matching per-runtime count, and mode0700; success text or an exit-zero install no longer suffices.

Source tree5f3753da254bb5685d64ce1051484495f8578124 passed path, usage, telemetry, license and runtime unit suites on all four feature owners. Counts: Arch26/19/12/16/9; Debian, Ubuntu and Fedora25/19/12/16/9. One ignored usage test is excluded. The rebuilt CLI passed fresh Node installation and a second switch with exact counts1 then2 under both telemetry modes on Debian, Ubuntu and Fedora. Arch's build initially crashed in LLVM (#451); an explicitly recorded diagnostic repetition completed, but its fresh Node installation then crashed during XZ extraction (#469). That Arch end-to-end test is not passing evidence.

The new runner fault-injection test first demonstrated false PASS results for missing, malformed, writable, wrong-runtime, double-counted and missing-command usage state. After adding the oracle,38 output, inventory-policy and network-scope tests passed. A subsequent single-document JSON constraint and its negative control passed the targeted runner test. The updated runner also exercised real Ubuntu installations through a local shell transport: Python and Go passed, while Node failed with the independently tracked XZ error. Local transport results are not hosted QEMU evidence and are not substituted for failed runs.

Related failures and preserved diagnostics remain in #467 (WSL stall), #451 (compiler crash), and #469 (intermittent extraction). #468 remains open until fresh hosted QEMU validates this implementation. The reviewed behavioral denominator,95% goal, and independent final review remain incomplete.

### Follow-on first-writer audit

The shared directory can also be created before runtime selection by history, audit logging/incompleteness markers, default SBOM export, completion-cache writes, snapshots, tool installation, and direct runtime staging/locking. These explicit state writers now use private creation; generic file-writing utilities and read-only path resolvers retain their existing behavior. Existing directories still are not chmodded.

New constructor regressions for history and audit first failed with mode0755 instead of0700, then passed after the change. Source tree9f8a618c14f0e541940180409c3e65a0b439394c passed the owning history17, audit25, SBOM2, completion11, snapshot3, tool15 and runtime-common60 unit tests on Arch, Debian, Ubuntu and Fedora; all four CLI builds completed. These are133 unit checks per distro, not133 newly covered behavioral contracts. Hosted evidence for this downstream change is still pending.

### Daemon-first nested socket path

A further first-writer review found `prepare_socket_parent` created missing ancestors with default permissions before chmodding only the socket leaf. Strengthening `prepare_socket_parent_creates_nested_dirs_owner_only` to inspect the data ancestor reproduced0755 instead of0700 on Debian. The implementation now uses the same private recursive creator and retains socket-parent validation without chmodding existing entries. All25 Debian path tests passed after correction, including existing unsafe-parent rejection. Other distro and fresh hosted validation for this addition remain pending.

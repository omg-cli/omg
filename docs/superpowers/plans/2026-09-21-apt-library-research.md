# APT library research and upgrade evaluation

Date: 2026-09-21. Requested during the CI/QEMU cleanup; no replacement backend or dependency upgrade is approved as complete by this document.

## Verified current state

- OMG uses Rust edition 2024 and MSRV 1.95.0. Cargo.toml requests rust-apt 0.10.0 and Cargo.lock resolves exactly 0.10.0.
- The live crates.io API reports rust-apt 0.11.3, published 2026-09-14, not yanked. Initial Exa search snippets still reported 0.10.0; direct registry and docs.rs verification corrected that stale result.
- The verified 0.11.3 crate archive identifies source commit `045d2a6cddca05e23f969c462ff429d248dd3932`. Its SHA-256 matched registry metadata before source comparison.
- OMG already combines pure Rust indexed metadata queries (`debian_db`, rkyv, memchr, rayon) with native APT operations. A process-wide mutex protects native cache use and destruction. Install currently delegates to authenticated native apt-get; root remove/upgrade/sync use native bindings. The optional pure Debian backend refuses production mutations.

## Candidates

| Candidate | Verified role | Assessment |
| --- | --- | --- |
| [rust-apt 0.11.3](https://docs.rs/rust-apt/0.11.3/rust_apt/) | Rust bindings to native libapt-pkg | First upgrade candidate; preserves APT semantics and existing architecture. |
| [oma-apt 0.13.0](https://github.com/AOSC-Dev/oma-apt) | Fork of rust-apt, still binds libapt-pkg | Not an escape from the native ABI. No verified evidence yet of a speed advantage for OMG's workloads. |
| [debian-packaging](https://docs.rs/debian-packaging/latest/debian_packaging/) | Pure Rust packaging/repository primitives and dependency traversal | Potential replacement for individual metadata helpers; not established as a complete APT transaction substitute. |
| [libapt](https://docs.rs/libapt/latest/libapt/) | Pure Rust repository parsing and metadata verification | Repository functionality, not established full installed-system transaction parity. Its documented detached Release.gpg limitation needs consideration. |
| [debrepo](https://docs.rs/crate/debrepo/latest/source/README.md) | Repository parsing/bootstrap, resolvo dependency solving | Interesting for isolated rootfs workflows; no established drop-in native APT replacement. |

Both binding projects explicitly caution against multithreaded native use. Retain serialization; do not add unsafe Send/Sync to obtain apparent throughput.

## Concrete upstream changes

Compared the downloaded 0.10.0 and 0.11.3 source archives. The latter adds RAII APT lock release, maps failed/incomplete install results to errors instead of panics, passes explicit string ends to native version comparison, and adds release-info change callbacks instead of the older unconditional acceptance implementation. Iterator index types change from u64 to usize. These are correctness and integration reasons to evaluate an upgrade; they do not prove a speedup or a vulnerability in every OMG path.

Also inspected the published 0.10.2 source (`1e8e57b03264eac82f5f5fac78c68f5f8d6ddf38`): it already contains the RAII guard, bounded version comparison and release-info callback. Do not attribute these improvements exclusively to 0.11 or claim a new minor release is required for every fix. Include 0.10.2 as a compatible-line baseline when evaluating 0.11.3; the current lockfile has received neither update.

Both versions still depend on the system libapt-pkg. Upgrading the wrapper does not make an APT6-linked archive load on an APT7-only host. Verified Debian package contracts: [Bookworm libapt-pkg6.0](https://packages.debian.org/bookworm/libapt-pkg6.0), [Trixie libapt-pkg7.0](https://packages.debian.org/trixie/libapt-pkg7.0). The artifact-routing/preflight work in #476 remains necessary.

## Evaluation sequence

1. Preserve the working native backend while completing APT6/APT7 release delivery and current failing gates.
2. Trial rust-apt 0.11.3 in an isolated branch. Inspect API changes, update only the necessary dependency graph, and verify native tests on both APT ABIs before proposing integration.
3. Add focused regression evidence for relevant changed behavior: version ordering (epochs/revisions and bounded substrings), failure lock release, failed/incomplete transaction propagation, and repository metadata change refusal. No production host mutations; use disposable QEMU transaction clones.
4. Measure exact-revision cold startup, warm search/info, missing-package queries, cache rebuild/invalidation, and resolver/transaction setup with daemon on and off. Require equivalent outputs and operation scope for comparisons. No "much faster" claim from crate version or Rust implementation language alone.
5. Investigate the current empty-search fast path: an empty successful Rust result falls back to opening native APT. This is a measured optimization candidate only after confirming completeness/correctness semantics. Benchmark warmup currently discards errors in debian_common; strengthen benchmark admission before trusting performance claims. The real-world search comparison also needs equivalent result scope, since OMG defaults to a result limit.

No dependency was changed during this research. No throughput claim, full native replacement claim, or broad standards-compliance claim is made.

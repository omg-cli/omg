# QEMU efficiency implementation plan

**Goal:** Shorten feedback without reducing checks or trusting cached execution state.
**Architecture:** Each x64 matrix entry calls one reusable build/guest workflow. Cache only pinned base-image bytes; verify restored bytes before use and retain fresh overlays. Keep native distro builds, guest isolation, published provenance and trusted failure reporting intact.
**Tech stack:** GitHub Actions, Bash, Python standard library, QEMU/KVM, Cargo.
**Spec:** User-authorized research and implementation; baseline ad500149 (PR #431).
**Execution:** Inline, no subagents, no paid runners or new services.

## Evidence and decisions

Exa research: nine searches, 45 requested result slots across scheduling, compilation, image reuse and cache trust; these are not 45 independently validated sources. Primary documentation below determines implementation, not third-party performance claims.

- [GitHub reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows): matrix callers can run independent multi-job workflows. Keep local references on the caller revision, contents:read, explicit conditional secret forwarding, and an always-running aggregate gate.
- [QEMU functional testing](https://www.qemu.org/docs/master/devel/testing/functional.html): precache pinned assets separately from test execution. Cache immutable base images, never guest disks, SSH keys or RAM state; verify digest even on a hit.
- [rust-cache](https://github.com/Swatinem/rust-cache): dependency caching is intentional; workspace caches and broad keys do not eliminate linking. Retain feature/distro/toolchain segregation.
- [sccache Rust limits](https://github.com/mozilla/sccache/blob/main/docs/Rust.md): linked binaries and proc macros cannot be cached; another cache layer is not justified by the present evidence.
- [nextest archives](https://nexte.st/docs/ci-features/archiving/): useful for compatible build/run environments, not proof that Debian/Ubuntu/Arch/Fedora tests are interchangeable. Retain serial libtest semantics and native builds.
- [GitHub cache security](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching): restored data is untrusted; default-branch read restrictions do not replace digest validation. Explicitly restrict saves to trusted main runs.

Measured PR #431 QEMU run 35024702965: staged builds 14m55s–17m46s; guests 4m47s–7m05s. All guests waited until 21:35:16Z; Debian build finished 21:32:23Z. Independent scheduling removes that dependency, but runner queues and the longest lane still bound total latency. No percentage speedup promised.

Main run 35045977829 subsequently passed. Its Debian Cargo report showed omg binary 137.6s, aws-lc-sys build script 132.66s, omgd binary 91.39s, and omg library 87.07s. Binary builds overlapped, so these durations cannot be added or treated as guaranteed wall-clock savings. Non-Arch archives exclude omgd: stop compiling that unused release binary while retaining every library/binary unit test. Arch still builds both release binaries.

## Implementation

- [x] Extract x64 build and guest jobs to `.github/workflows/qemu-lane.yml`, call once per selected distro; preserve build features, containers, release packaging, serial unit tests and all guest arguments. Keep ARM health boundary and dispatch-only eligibility.
- [x] Update workflow regression tests to inspect the reusable file; execute staged/published selection and failure/cancellation/missing-job cases. Keep `QEMU matrix result` fail-closed and release gate names stable.
- [x] Add `scripts/qemu-image-cache.py` for digest-verified atomic copy. Missing/corrupt cached data must never be executed. Test SHA256/SHA512, damaged bytes, symlinks, invalid writes and destination preservation.
- [x] Wire optional `--image-cache` into the harness; cache only the pinned distro/architecture image. Restore/save with SHA-pinned Actions. Only trusted default-branch runs save shared image caches. Hash the actual image in the controller before boot and retain manifest verification.
- [x] Select only packaged release binaries in staged builds (`omg` everywhere, `omgd` additionally on Arch); retain all existing `cargo test --lib --bins` checks.
- [ ] Run focused workflow, image, provenance, process-isolation, inventory, egress and reporting regressions plus Bash syntax/YAML checks. Review full diff, commit and open a `perf(ci):` PR; examine actual hosted results before claiming success.

## Decisions against speculative work

Do not remove duplicate-looking Rust tests until equivalence is demonstrated across profiles, features, ABI and libtest/nextest semantics. Do not adopt a prebuilt controller until its automated refresh and vulnerability-floor checks are designed and tested: the present apt update and controller floor protect against stale vulnerable QEMU. Do not introduce paid runners, mutable VM snapshots, root fallback, relaxed egress, or cross-trust compiler caches.

## Acceptance

Every selected lane must succeed; failed/cancelled/missing builds or guests reject the overall result. Published checks still resolve release inventory and verify attestations before guest execution. PR execution gets no telemetry secret or issue-write permission. Cache corruption fails safely or is treated as a miss before a verified download. Report cold/warm timings separately; hosted QEMU remains required evidence.

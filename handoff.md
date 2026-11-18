# OMG v0.1.225 Linux handoff

Snapshot from November 18, 2026. Fetch `origin` and recheck the PR heads and required checks before updating a branch.

| Reference | Commit | State at handoff |
| --- | --- | --- |
| `origin/main` | `b486614a` | Current base for both PRs |
| `origin/ci/full-gate-followthrough` | `d7b4940a` | [PR #1056](https://github.com/omg-cli/omg/pull/1056) is open |
| `origin/codex/arch-hardening` | `8799bfd7` | [PR #1057](https://github.com/omg-cli/omg/pull/1057) is open |
| `origin/codex/v0.1.225-linux-handoff` | `ac8026e5` | Prepared integration source before this document |

The handoff branch includes both PR heads and the prepared conflict resolutions. Use `ac8026e5` for the code integration and keep this note on the handoff branch. The Windows checkout has 14 pre-existing edits outside this batch.

## 1. Finish #1056 first

- **Workflow helpers** failed in `test_ci_gates.UbuntuMirrorSetupTests.test_ca_bootstrap_precedes_exact_https_rewrite_and_stops_failures`. The fixture expects kernel.org to be the sole mirror and treats the first failed update as terminal. Align it with the signed Canonical-first fallback and retain assertions for CA bootstrap order, signature enforcement, and failure when both mirrors fail. [Failed job](https://github.com/omg-cli/omg/actions/runs/44393070008/job/135115913792)
- **Security Audit** found three vulnerabilities. `quinn-proto` 0.11.18 needs 0.11.19 or later for `RUSTSEC-2026-0523` and `RUSTSEC-2026-0524`. `quinn-udp` 0.5.14 needs a patched release such as 0.5.16 for `RUSTSEC-2026-0538`. Check the affected lockfiles and rerun the audit on the updated commit. [Audit job](https://github.com/omg-cli/omg/actions/runs/44393069907/job/135115601322)
- The instrumented coverage job was running. Wait for the exact-base comparison and inspect its evidence if it fails. The batch keeps the comparator and thresholds intact and adds a required IPC isolation fixture. [Coverage run](https://github.com/omg-cli/omg/actions/runs/44393069975)
- Merge #1056 with a merge commit after `CI Success` and `Generate Coverage Report` pass on the current head and the branch is up to date. Preserve the pinned pre-checkout action commit in the merged history. [CI run](https://github.com/omg-cli/omg/actions/runs/44393070008)

## 2. Integrate and merge #1057

- Update #1057 against the resulting `main`. Reconcile the prepared code with any newer PR changes and carry forward the #1056 fixture and audit fixes. Keep the native platform and coverage gates intact.
- The `8799bfd7` coverage run rejected retained-line correspondence. Its comparison artifact contains the exact base and candidate reports. The new base after #1056 changes the comparison. Use the fresh integrated report to decide which gaps remain. [Previous #1057 coverage](https://github.com/omg-cli/omg/actions/runs/44383943967)
- The prepared candidate passed focused native tests for bounded, root-owned Arch keyring lists, Node publisher manifest authentication, and Pi package publication. The combined workflow fixture also passed locally. Full hosted validation is pending.
- Skip #1038. `main` already covers its Python catalog assertion.

## 3. Publish and verify signed v0.1.225

- After #1057 merges, verify the exact `main` commit through the release workflow. The tag gate also requires Cloudflare publisher-archive verification. Live status reported 424,926 imported records and `caught_up: true`, with `archive_verified: false` and `bootstrap_complete: false`. Follow the main-branch advisory refresh workflow and verify `python3 scripts/advisory-baseline.py status`. [Worker status](https://omg-advisories.latham.workers.dev/v1/status)
- Confirm the GitHub release, checksums, and artifact attestations before installing the released binary on Ubuntu 26.04 WSL. The compatible Debian Trixie artifact is the intended WSL verification target.
- Repeat the npm CVE refusal in a disposable WSL directory with `vite@6.2.2` and `CVE-2025-30208`. Verify a nonzero exit, a visible advisory link, and no package materialization. The earlier candidate passed refusal checks on blank Enter and noninteractive `--yes`. The signed release acceptance is pending. [Advisory](https://osv.dev/vulnerability/GHSA-x574-m823-4x7w)

At handoff, neither PR was merged and `v0.1.225` was unpublished.

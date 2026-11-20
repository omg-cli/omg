# Advisory Risk Consent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Work solo in the existing checkout.

**Goal:** Warn about affected or watch-listed package/runtime versions with advisory links, and install them only after explicit scoped user acceptance.

**Architecture:** Build a canonical advisory-risk review from the actual resolved subjects and provider evidence. The transaction owner checks source/integrity policy, issues the review, and accepts only a decision bound to that review and transaction. Terminal rendering and input are adapters; generic `--yes` and client-supplied finding counts are not authority. Reuse native prepared-transaction digests and attended acknowledgment instead of creating a parallel installation path.

**Tech Stack:** Existing Rust policy/scanner, CLI confirmation, native ALPM transaction owner, package service, daemon/TUI and runtime managers. Existing SHA256/serialization primitives; no new dependency.

**Spec:** docs/superpowers/specs/2026-11-16-advisory-coverage-design.md, especially the explicit user decision section.

## Global Constraints

- Default No; no implicit acceptance through generic --yes, EOF, missing TTY or I/O failure.
- Exact resolved versions and dependencies, source evidence and user/principal scope bind the decision. Changed evidence or selection requires a new decision; volatile revalidation timestamps alone must not invalidate an unchanged report.
- Accepted findings keep their severity, applicability, provenance and Unknown/partial coverage. Acceptance never means safe or patched.
- Advisory acceptance does not lower source/trust grades or disable banned-source, license, signature, integrity or transaction checks.
- Do not label a possible match or prediction as confirmed exploitation. Keep unsupported package/runtime mappings Unknown.
- Keep ordinary default paths covered; do not leave warnings available only to custom policy users. Preserve documented explicit coverage-mode choices and test any intentional contract change.
- Never add a global persistent accept-all setting or environment-variable bypass. No automatic URL opening or raw terminal control sequences from provider text.
- Existing main only, no new branch/worktree, push only HEAD:codex/arch-hardening. Original coverage and native acceptance gates remain unchanged.
- No Cloudflare mutation or spend until account quota/credit coverage is verified.

## Review Focus

- Generic --yes and noninteractive callers must not silently accept a newly discovered advisory.
- A dependency or resolved runtime alias can introduce a risk absent from the user's original target string.
- A replayed acknowledgment must not authorize changed versions, findings, policy, principal or native artifacts.
- Cancellation must not produce an installation-success message or successful-install history entry.
- Malicious advisory text/URLs, absent CVE aliases, stale data and incomplete mappings must not produce terminal injection or a false clean report.

## Implemented Arch slice

The first implementation uses `core/security/advisory_review.rs` and the native `alpm_ops::confirm_advisory_prompt` terminal owner. There is no unattended acceptance flag: callers without a suitable controlling terminal refuse disclosed risk. The user types `accept <review-id>`; generic `--yes` does not supply that answer. A review ID binds all resolved subjects and findings plus the existing policy/profile/principal/archive digest. The terminal lists packages with findings; unaffected dependencies remain in the digest without expanding the warning.

Native Arch admission attempts the snapshot lookup even in built-in `optional` mode. Provider failures in that mode remain Unknown and print a warning. Findings in every mode require consent, including Possible matches from sources without established applicability. Source and archive enforcement runs before consent, and commit-time validation rechecks receipt freshness, identities, policy, principal, artifacts and the acceptance. Preflight defers Arch advisory decisions to this owner.

Local evidence includes real controlling-PTY accept/refuse cases, a deliberate generic-answer bypass caught by the rejection test, and a large-upgrade regression that first failed the display bound. Related policy parsing/source/dependency tests and Arch all-target Clippy are also required. These checks do not establish full install-to-commit acceptance or support on other backends.

The disposable native-owner drill now passes eleven cases with a synthetic HTTPS advisory source and actual libalpm writes in a private package root: acceptance installs the exact fixture; generic yes, blank, wrong ID, EOF, no TTY, changed archive, changed policy, actual terminal Ctrl+C, SIGTERM and SIGHUP leave the file and local database uninstalled. Each cancellation reports an interrupted admission. An omitted-interrupt control that sends acceptance instead makes the cancellation fixture fail. The policy-change case runs last because these cases share the disposable home. This is native-owner proof, not complete CLI/sudo/history/progress or Windows/npm proof. The coverage runner collects the fixture's actual profiles through its normal expected/passed test accounting, with its original deadlines.

Remaining work: full CLI/sudo/history/progress verification, terminal cancellation/foreground fault coverage, runtime vendor applicability and activation gates, other native backends, and full immutable-base/public/native acceptance. Keep the original goal active until those requirements are verified.

## Preflight boundary correction

Hosted d6fce696 exposed three failures. Local reproduction confirms them: broad Arch deferral skipped explicit Review inventory validation, allowing a mock update to proceed and an AUR fixture to reach another metadata request. Restore the Review lookup and exact inventory check before handoff. Optional and final-only FreshSnapshot retain their preflight lookup behavior. Source/license checks remain mandatory; valid findings alone defer to native consent. Keep the two service no-mutation assertions unchanged. Update the CLI finding test to prove successful handoff and retain its exact typed Risk/Community policy rejection using the reported finding. Re-run both affected test modules, the review model, relevant policy controls, Clippy and hosted gates. Do not label the native install/commit drill complete until it runs.

The correction passes all 81 tests in the four affected modules, plus the separate no-terminal regression and five real controlling-PTY cases. Arch all-target Clippy, formatting and diff checks pass. Hosted acceptance and the actual install/commit drill remain open.

### Task 1: Canonical risk review and advisory links

**Files:** Add src/core/security/advisory_review.rs; wire its module in src/core/security/mod.rs. Reuse types from scan.rs, vulnerability.rs and package_managers/types.rs. Add focused tests in the new module.

**Interfaces:** Crate-private AdvisoryRiskReview records the resolved subjects, findings, source/confidence and references and exposes a canonical review ID. AdvisoryRiskAcceptance is opaque; it cannot be deserialized from an unchecked boolean. Runtime adapters must supply genuine vendor/runtime coordinates, not pretend to be distribution packages.

- [ ] Add failing tests for Applicable versus Possible findings, multiple packages/dependencies, no-CVE advisory IDs, deterministic ordering, duplicate reports and changed version/evidence invalidation.
- [ ] Generate safe HTTPS links from verified provider references or canonical CVE/OSV IDs; test terminal control characters, malformed URLs and missing references. Preserve all displayed IDs; never silently truncate the accepted set.
- [ ] Implement the smallest review model with existing serialization/SHA256. Bind semantic evidence, not display color or a changing checked_at timestamp. Keep source/freshness separately available for commit-time validation.

### Task 2: Explicit terminal decision and unattended handling

**Files:** Reuse the actual CLI confirmation module after locating it with rg --files; add the review adapter alongside the existing package UI. Inspect cli/packages/install.rs, cli/runtimes.rs and CLI argument definitions before choosing exact plumbing. Preserve existing stdout contracts where machine output already exists.

**Interfaces:** Render the full risk review and read a distinct default-No security confirmation. If noninteractive acknowledgment is supported, use an explicit review ID from the blocked/current review and validate it against the recomputed report; it is scoped to this invocation, not saved globally.

- [ ] Add failing adapter tests: explicit yes accepts, blank/no/EOF/cancel/I/O failure declines, --yes does not answer this prompt, missing TTY refuses, and a wrong/old review ID refuses.
- [ ] Display subject/version, advisory ID and URL, source/confidence, and a known fix only when available. Print advisory warnings even when an explicit automation acknowledgment is provided.
- [ ] Reuse the existing attended TTY/principal validation used by native archive acknowledgments. Keep its existing stronger semantics intact; do not weaken archive consent just to share input code.

### Task 3: Enforce consent at the real mutation boundary

**Files:** core/packages/service.rs; cli/packages/install.rs and install/arch.rs, debian.rs, generic.rs as applicable; package_managers/alpm_ops.rs; existing policy.rs advisory gates; runtime manager admission boundaries as their vendor providers become available. Inspect every caller before edits.

**Interfaces:** Source/integrity policy remains mandatory. Advisory findings cause ReviewRequired until a matching acceptance is supplied. The prepared owner validates the report and exact transaction before commit; direct/daemon callers have no implicit acceptance. Do not introduce a raw allow-risk boolean that skips all policy checks.

- [ ] Add failing behavior tests proving a known advisory prompts under default user-facing configuration and a decline causes zero install/activation calls and no successful history entry.
- [ ] Add an accepted-risk test proving the exact selected version can install, while changed dependencies, versions, evidence, policy, principal or artifact bytes require revalidation/new consent.
- [ ] Exercise both Applicable and Possible/watch-list cases and preserve explicit partial/Unknown source results. Default advisory lookup behavior and unavailable-provider handling must be tested deliberately rather than inherited from the current Optional early return.
- [ ] Update preflight gates so they do not permanently reject a finding the final owner can present for acceptance. Do not let this defer a source/license/signature denial or let a backend lacking final consent enforcement bypass it.
- [ ] Keep accepted findings Risk in audit/SBOM/export data. Test that risk consent cannot authorize unrelated policy violations or forged finding counts.

### Task 4: Complete caller coverage and real verification

User acceptance requirement: once npm admission is operational, install a verified OMG build in the user's supported Windows WSL environment and exercise an npm package installation through OMG-managed execution. No native Windows executable is currently supported. Use a known-vulnerable package version with a real advisory URL; prove default refusal before package installation or lifecycle execution, and retain the explicit transaction-bound override. Do not present the Arch fixture as Windows/npm proof. Preserve the user's existing Node/npm installation and environment. Record the installed OMG path/version, the exact test command and observed result. The user has authorized this local installation once the gate is operational; no repeat permission question is needed.

Extend the existing private-root native consent drill with actual terminal Ctrl+C, SIGTERM and SIGHUP while the acknowledgement is pending. Each must report an interrupted admission and leave both installed files and the local ALPM database unchanged. Reuse the normal profile accounting and preserve all existing deadlines. This establishes native-owner cancellation only; full CLI/sudo/history/progress and foreground-change cases remain required.

The native install drill will add an explicitly provisioned ignored fixture to `alpm_ops.rs` and a Bubblewrap/PTY driver in `scripts/test-arch-advisory-consent.py`. Reuse the existing oracle's synthetic feed, hosts and NSS helpers; keep its QEMU-only main unchanged. Use the fixed production HTTPS endpoint with a fixture CA/DNS only inside private mount/network namespaces. Install a harmless local archive into the existing disposable ALPM root/database fixture. Cover acceptance, generic yes, blank, wrong review, EOF, no TTY, changed archive and changed policy. Assert actual installed file/localdb state, request count, review classification and exact failure reasons. Wire the driver into the native coverage fixture runner after it passes locally; its test identity and profiles must enter the existing expected/passed evidence rather than bypassing that accounting.

The prior 95889dae coverage producer passed its ordinary tests but timed out in the supplemental QEMU harness before comparison. Its exported Omarchy transcripts contain repeated unavailable-provider warnings. Keep that fixture's provider explicitly unavailable on private loopback, with local hosts-only resolution and a refused-port probe, so offline DNS cannot consume request deadlines repeatedly. Preserve Unknown coverage and every existing deadline. A separate HTTPS fixture exercises actual advisory findings. The exact generated offline setup passes in private namespaces without changing host hosts/NSS files; full hosted producer acceptance remains required.

**Files:** Existing CLI/daemon/TUI mutation paths, cli/runtimes.rs, direct runtime-manager callers, help/docs and relevant behavioral tests. Use the code inventory to pin exact files before implementation.

- [ ] Inventory install, upgrade, aliases, use/activation, restoration, direct manager and daemon/TUI paths. Each supported path must either perform explicit scoped review or return ReviewRequired without mutation.
- [ ] Integrate runtime provider results into the same visible decision semantics. Report unsupported vendor/version mappings; do not synthesize a match from a CVE ID or npm package named node.
- [ ] Run focused RED/GREEN tests and a real isolated native decline/accept/change-between-review-and-commit drill. Add controlled generic-yes/bypass faults and prove the rejection tests turn RED.
- [ ] Run relevant native lint, formatter, public CI and source-correspondence checks within storage budgets. Review the complete diff and report remaining platform/provider gaps. No release claim until complete paths, gates and review are verified.

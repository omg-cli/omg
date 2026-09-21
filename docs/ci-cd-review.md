# CI/CD and QEMU delivery review

> **Who this page is for:** OMG maintainers and contributors. It documents a dated review of the continuous-integration setup.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

Security is the primary constraint on delivery performance. Optimizations must
preserve test coverage, credential boundaries, and verifiable release provenance.
This review covers OMG and its companion website. Findings and implementation
evidence below are current to September 14, 2026; validation is still in progress.

## Workflow coverage

| Workflow | Distinct purpose | Review decision |
| --- | --- | --- |
| CI | Formatting, lint, portable and backend tests, macOS, root-sensitive sandbox checks | Preserve backend and privilege coverage. Stable aggregate result must reject failed or unexpectedly skipped jobs. |
| Code Coverage | Instrumented Arch tests and LCOV/HTML reports | Preserve: reports already reuse one test execution. This is not three duplicate suites. Cache freshness remains under review. |
| QEMU Matrix | Real kernels, reboot, package transactions, inventory and packaged binaries | Preserve guest coverage. Add signed release verification, non-root QEMU, syscall restrictions, runtime isolation assertions and compiled dependency caches. |
| Docker E2E | Container orchestration and product Docker integration | Preserve: does not duplicate guest kernel and reboot coverage. |
| Release | Platform packaging, attestations, publication, R2 synchronization | Require CI, benchmark, audit, secrets, CodeQL, coverage, Docker and staged QEMU on the release revision. |
| Release Smoke | Published packages on four Linux backends and native macOS | Preserve as post-publication coverage; remove PR telemetry credentials. |
| Benchmark | Reproducible benchmark results and published records | Preserve separate performance evidence. Require the exact release source revision. |
| Security Audit | Rust vulnerability, license, source and dependency policies | Preserve audit and deny checks; overlap is not enough evidence to remove either. |
| CodeQL workflow analysis | Security queries against GitHub Actions definitions | Added as a distinct scan, with workflow/action changes included in triggers. |
| Secret Scanning | Gitleaks and TruffleHog | Preserve complementary detection pending evidence of equivalent coverage. |
| Scheduled Fuzzing | Bounded sanitizer campaigns with persistent corpus | Fix explicit nightly and GNU target selection. Keep all three campaigns. |
| Mutation Testing | Quality of security-related tests, including missed mutants | Preserve the score gate and zero-mutant failure. Full campaign result remains to be checked. |
| Changelog | Release communication generated from local history | Generate offline; remote metadata adds no value to current templates. Daybreak separately isolates the publishing job. |
| Website CI | Source policy, type checks, audits, migrations, Worker/site builds, unit tests and public browser journeys | Preserve independent browser journeys. Separate prerelease adapter upgrades from unrelated dependency updates. |

## Confirmed improvements

The prior CodeQL run spent 370 seconds compiling release binaries before its
Rust extractor independently ran. GitHub lists Rust as supporting `none` build
mode, not the traced manual build modes used for some other languages. The
workflow now states that mode explicitly and omits the redundant release build.
The pinned Rust installation and existing security-and-quality suite remain.
Compare extraction diagnostics and total hosted duration before claiming savings.
[GitHub build modes](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages)

QEMU staged builds previously cached only downloaded dependencies. The replacement
uses the already pinned Rust cache action to retain compiled dependencies, with
separate architecture/distro/job keys and a hash of the workflow containing the
container and feature configuration. Compiler and Cargo configuration also
participate in the action's key. Workspace outputs are rebuilt, cache saves require
successful jobs, and installed tools are excluded. These caches are not used as
release attestations or promoted into privileged publication jobs.
[Rust cache design](https://github.com/Swatinem/rust-cache)

Cache isolation is a security boundary. Pull-request cache writes are scoped to
the PR merge ref; default-branch or release workflows must not consume PR-created
executables through an added cross-workflow promotion path. A cache miss must
affect performance, not correctness. No shared release artifact cache has been
introduced. [GitHub cache scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)

Release Smoke now omits Sentry configuration on PR events, matching QEMU. Secret
scoping must account for same-repository PRs as well as forks. This prevents
routine PR execution from receiving the telemetry credential; it does not replace
repository access controls against collaborators who can edit workflows.
[GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use)

## QEMU trust boundaries

Published archives now require an attestation matching the repository, release
workflow, source tag and resolved source commit before preparation emits a usable
inventory. An adjacent checksum alone can be replaced with its archive. The
existing checksum, inventory digest, input validation and moving-tag rejection
remain. The Debian v0.1.220 archive passed a real verification with these constraints.
Invalid-attestation regression tests prove preparation fails before publishing its
contract. [GitHub attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

The QEMU process must run as UID/GID 65534, with all real/effective/saved/filesystem
IDs checked, zero effective capabilities, no-new-privileges enabled, and seccomp
filtering active. The controller prepares devices as needed, then QEMU drops its
identity before executing the guest. The monitor is disabled; obsolete syscalls,
process spawning and resource-control operations are restricted. QEMU 7.2 supports
the selected options. Setting setuid restrictions before QEMU's own privilege drop
would prevent startup, so the runtime assertion verifies the resulting boundary.
[QEMU security](https://www.qemu.org/docs/master/system/security.html),
[QEMU 7.2 option definitions](https://github.com/qemu/qemu/blob/v7.2.0/qemu-options.hx)

The first hosted test correctly failed when QEMU's daemonization fork collided
with spawn denial. The corrected launch uses a controller-owned background
process, retaining spawn denial. Debian run 34904901174 then passed, recording
the unprivileged process state, a changed guest boot ID after reboot, and verified
controller removal. Published-release run 34905703515 subsequently passed all four
guests (Arch, Debian, Fedora and Ubuntu), including the aggregate result. Staged
build and guest evidence remains required before merge. Container setup remains privileged within its namespace;
this is a reduction in guest-process privilege, not a claim of perfect isolation.

Existing safeguards retained include pinned images, mandatory KVM without TCG
fallback, user-scoped host KVM access, pinned SSH host identity, disposable disks,
bounded allowlisted evidence export, teardown verification, and separate lifecycle
and inventory verdicts. Guest image update authentication, egress limitations,
resource exhaustion, and reporting failure handling remain part of the ongoing
review; they are not declared resolved by this patch.

## Release decisions

### Operator compatibility changes

This patch intentionally tightens the CI/harness contract without changing the
public OMG CLI or Rust API. Published-mode operators must select an attested release
from this repository's release workflow; old checksum-only archives are rejected.
QEMU must support the enforced UID/GID and seccomp state; there is no root or
unfiltered fallback. Release automation must have successful current push runs for
all prerequisites listed below. A PR or partial manual run cannot substitute for
that evidence. These requirements apply when the workflow changes land, independently
of the crate version; a subsequent product release receives its own version bump.

The prerequisite helper now checks the newest push-triggered run for the exact
commit. An older green run must not hide a newer failure, cancellation, or skip.
PR merge revisions and partial manual runs cannot authorize publication. Main
pushes run the staged x64 guest matrix; configurable ARM runners remain available
only through explicit staged dispatch. Release publication waits for the security
and guest prerequisites as well as the original CI/benchmark gates.

Release builds remain distinct from ordinary CI binaries: platform packaging,
compiler flags, and attested tag provenance are meaningful differences. Reusing
those artifacts would require a proven equivalent build and trustworthy producer
identity, not simply matching a filename. R2 retains round-trip verification before
updating the version marker. Final release and post-release smoke evidence are
still required.

## Website compatibility

The dependency PR upgrades SvelteKit beyond the adapter API supported by Alchemy.
Inspection of the current Alchemy beta.77 package confirmed it still calls the
removed `generateManifest` method. Keep the deployed next.25 SvelteKit version
while accepting compatible dependency fixes, and group future Kit/Alchemy upgrades
for separate review. Automatic updates remain enabled; no permanent upgrade
suppression is introduced. [Renovate grouping](https://docs.renovatebot.com/configuration-options/#groupname)

The newer Better Auth initializes database schema validation on anonymous session
lookups. Requests with neither Cookie nor Authorization credentials now return an
anonymous result before provider initialization; requests carrying either header
still use provider validation. The existing missing-platform failure remains.
The site build and bundle budget pass, and all 314 site tests pass after this fix.
Full website CI and public browser journeys remain required.

## Validation record

- PR #415 merged after its checks passed; bounded fuzz run 34904379805 also passed.
- Published QEMU run 34905703515 passed Arch, Debian, Fedora and Ubuntu.
- The public rust-cache namespace triggered Gitleaks' generic API-key heuristic.
  Its exception requires the exact input line AND workflow path and applies only
  to that rule. Gitleaks 8.30.1 passes the branch history; negative controls confirm
  a changed token and the same label in another file remain detected.
  [Gitleaks configuration](https://github.com/gitleaks/gitleaks#configuration)
- All OMG workflows pass actionlint 1.7.12 syntax/expression validation locally.
- QEMU preparation: four focused contract/attestation tests pass.
- Process isolation guard: valid state accepted; missing state, root IDs,
  effective capabilities, missing no-new-privileges and missing seccomp rejected.
- Release prerequisites: five tests cover success, waiting, failed completion,
  missing evidence and latest failed/cancelled/skipped runs.
- Release boundary tests: nine pass. QEMU workflow selection tests: fourteen pass.
- Hosted all-platform verification, complete security PR integration, release
  publication, final performance comparisons and issue closure are outstanding.

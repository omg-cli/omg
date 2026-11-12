# Arch audit and implementation plan

The target is a usable Arch backend with current official Rust ALPM components,
an explicit C libalpm transaction boundary, and an optional restrictive AUR
mode. Work stays in the existing checkout. No local branches or worktrees.

## Approach

Update the official Rust metadata and database crates together at one immutable
upstream commit. Retain C libalpm for transaction preparation, dependency solving,
signature enforcement and commit. Upstream's published component list does not
provide a complete replacement for these operations. A transaction rewrite
would need separate compatibility and destructive-operation testing.

Audit the existing AUR controls before changing them. A sandbox protects the
build host, while an installed package can still run malicious code. Repeating a
build does not establish that its source is trustworthy. A restrictive mode
must state what it rejects and must refuse conflicting configuration.

## Work and verification

1. Map pure Rust queries, C calls, AUR source review, build isolation, archive
   inspection and privileged transaction admission. Record source-backed gaps.
2. Run an independent static security review of `src/package_managers/aur`.
   Track its actual scope separately from the broader Arch compatibility review.
3. Establish focused native Arch tests before changing behavior. Compare
   database and dependency results with libalpm on disposable fixtures.
4. Refresh the Rust ALPM family from types 0.11.2, srcinfo 0.6.3, db 0.2.2 and
   repo-db 0.1.2. Verify current upstream releases and adapt changed APIs.
5. Fix reproduced query, metadata and package-admission defects. Add regression
   tests at the affected boundary, then run the related existing tests.
6. Add a typed restrictive AUR setting if the review confirms that existing
   settings cannot express the desired admission rules. Keep ordinary behavior
   compatible. Refuse silent downgrade of the restrictive mode.
7. Build the checkout CLI and exercise read-only operations against the real
   Arch database with isolated OMG state. Do not install or remove host packages.
8. Review the final diff, record checks and remaining work, commit locally, and
   prepare a PR. A PR needs a distinct remote head; resolve that GitHub constraint
   without creating a local branch or pushing changes directly to remote main.

## Build ownership and storage

This host is native Arch, not WSL. Initial filesystem usage was about 52 GiB
with 876 GiB available. The first test target belongs to this audit at
`~/.cache/build-targets/omg-arch-audit`, initially budgeted at 12 GiB. The native
budget was raised to 16 GiB before the default PGP build, after the target reached
11 GiB and the host still had more than 800 GiB available. Monitor its
size during compilation. Retire superseded generated output once tests and the
final CLI proof no longer need it. Preserve compact proof and active failure
evidence. No release or coverage acceptance settings change to save storage.

## Upstream evidence

- [Official Rust ALPM repository and component list](https://github.com/archlinux/alpm).
- [Types 0.14.0 release snapshot](https://github.com/archlinux/alpm/tree/7342c1d0b60633d646a87bc1ce53f8c28ea65f9b).
- [Types changelog at that snapshot](https://github.com/archlinux/alpm/blob/7342c1d0b60633d646a87bc1ce53f8c28ea65f9b/alpm-types/CHANGELOG.md).
- [Database changelog](https://github.com/archlinux/alpm/blob/7342c1d0b60633d646a87bc1ce53f8c28ea65f9b/alpm-db/CHANGELOG.md).
- [Repository database changelog](https://github.com/archlinux/alpm/blob/7342c1d0b60633d646a87bc1ce53f8c28ea65f9b/alpm-repo-db/CHANGELOG.md).

These upstream pages and manifests were inspected on November 11, 2026. The
candidate snapshot contains types 0.14.0, srcinfo 0.7.0, db 0.3.0 and repo-db
0.2.0 and declares the same Rust 1.95 minimum as OMG.

## Findings and results

The independent static review read all seven original files in
`src/package_managers/aur`, including their tests. A separate reviewer checked
the patch. Supporting Arch database, configuration, archive-handoff and ALPM
code was inspected for the relevant dataflows. This is not an exhaustive audit
of every Arch transaction operation or every supported system configuration.

| Finding | Result |
| --- | --- |
| Rust ALPM pins lagged released metadata/database APIs | Updated all four direct dependencies to one immutable November release snapshot; adapted the removed `inner` API and the newly validated serde boundary. |
| Rust orphan counts ignored dependency/provision versions | Reproduced against isolated native libalpm databases, then reused complete versioned relations for direct and virtual dependencies. |
| Auxiliary source filenames could control the review terminal | Escaped displayed names and hook/symlink diagnostics while preserving raw filesystem and manifest bytes. |
| Rust/native archive interpretations disagreed | Added a bounded raw-metadata pass. Duplicate and unsupported PAX metadata, canonical attribute aliases, NUL names and mixed GNU/PAX names fail before admission. Raw and PAX sizes must agree. |
| Hardlink data could change the target inode's mode | Nonregular archive members carrying data are refused. Link privilege metadata is included in classification. |
| Encoded capability names escaped classification | Attribute classification follows libarchive's decoded LIBARCHIVE names; invalid or ambiguous names fail. |
| Single-frame decompression hid later archive members | Shared bounded decompression now consumes concatenated zstd frames and gzip members in both inspection and identity reads. Regression fixtures contain inert marker data. |
| Existing settings could not express restrictive AUR admission | Added the typed `standard`/`hardened` profile, config CLI support, conflicting-setting rejection and per-output admission checks. Hardened source confirmation remains attended even with `--yes`. |
| Disabled build-cache branches still hashed inputs and described reusable output | Removed unreachable production cache-hit branches and redundant cache hashing. Legacy cache helpers remain test-only. Default cache requests are off, and examples describe invocation-local storage. |
| RustSec published an xattr buffer soundness advisory during CI | Raised rustix to 1.1.6 in the manifest and both lockfiles. Doctor now uses the explicit attribute-length query API. |

The native archive checks used libarchive 3.8.11 and harmless temporary marker
files under an unprivileged account. They performed no package installation or
payload execution. A single PAX size override is supported consistently by the
two libraries, but this admission format deliberately requires equal raw/PAX
sizes so the validation pass can use unambiguous raw boundaries. Unsupported
archive metadata now fails explicitly rather than relying on parser tolerance.

The review considered `/lib` aliases but found native ALPM extraction already
enables `ARCHIVE_EXTRACT_SECURE_SYMLINKS`. That hypothesis was not promoted to a
finding. Source symlink policy and cache documentation were corrected to match
their actual consumers.

## Verification receipt

The run used Rust 1.95.0, native libalpm 16.0.1 and the normal default feature
set, including PGP and licensing. No release or coverage profile was changed.
The local GNU linker emitted an invalid relocation in the first test binary;
subsequent verification used a task-local GCC driver wrapper selecting the
Rust toolchain's LLD. The repository linker configuration is unchanged.

Fish and libclang build prerequisites were supplied from official Arch package
archives in the task cache. Their detached signatures were verified against the
installed Arch keyring. Neither package was installed into the host database.
`LIBCLANG_PATH` and the bindgen resource directory were explicit local run
settings. No incremental/debug profile overrides were used.

The target briefly crossed its 16 GiB budget during all-target linting. The next
native wave was stopped, obsolete intermediate test variants were retired, and
the target was remeasured below budget before resuming. A compact retirement
receipt records old binary hashes. The original loader-failure binary and its
referenced debug companions remain available; current proofs were preserved.

The CI followup raised this task's native target budget to 20 GiB before
all-target linting and the final CLI rebuild. The host had 793 GiB free.
Superseded passing library-test artifacts were retired with hashes recorded.
The original unresolved linker evidence remains intact.

Final checks passed:

- `cargo test --locked --lib --test arch_cli_contracts --test version_tests -- --test-threads=1`:
  2,112 library tests, 15 Arch CLI contracts and 18 version tests passed. Four
  existing library tests remained ignored.
- `cargo clippy --locked --all-targets -- -D warnings` and `cargo fmt --all --check`.
- `python3 scripts/check-alpm-pins.py` and its four negative/positive guard tests.
- The 21 CI gate tests and six change-classification tests passed after wiring
  the snapshot guard into the existing workflow.
- The documentation checker recognizes `aur.security_profile`; its 11 tests
  pass. The hardened-settings fixture uses the existing unprivileged runner
  when launched as root, preserving production root environment protection.
  A namespace-root run verified the child UID was 65534 and all assertions ran.
- The checkout-built default-feature CLI passed doctor, official search,
  installed glibc information, fast/full status and `outdated --json` checks.
  Doctor verified 1,009 installed packages and reported only the expected
  disposable-state daemon/hook warnings. The update result was an empty JSON
  array. Each drive preserved the host pacman database fingerprint.
  After the dependency followup, the rebuilt CLI's doctor verified 1,027
  packages with the same two expected warnings. Fast status reported the same
  installed count and preserved its own before/after database fingerprint.

The native proof's metadata/extraction comparisons used 31 bounded cases with
inert data. The retained initial static scan reported terminal rendering and
left native-parser hypotheses open; the later defensive fixtures and regression
tests resolved those hypotheses for the inspected native library version.
The scan is historical evidence for the initial source, not a certification of
the patched program or the entire repository.

The first PR run found [RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486),
published on November 11. The lockfiles contained affected rustix 1.1.4.
The followup uses patched 1.1.6 and `getxattr_query` for doctor's capability
presence check. The existing absent-attribute and missing-file test passed
before and after the API migration. The dependency-policy check now passes
advisories, licenses, bans and sources without changing exemptions.
Independent Rust reviews found no blockers in the API migration, lockfile
changes or root-fixture correction. They treated internal CLI code as
application code and checked correctness before style.

## Followup coverage and native builds

The next hosted run passed the platform, guest, security and instrumented-test
jobs. Coverage comparison refused the two added source modules before examining
their lines. The comparator now admits genuinely new files only when both
summary and mapped lines are fully covered. It compares the common files
separately so additions cannot conceal a regression. Removed files and
previously uninstrumented existing files still require review.

A separate source-correspondence check handles repeated covered fragments
inside a unique function with multiple compiled copies. It checks every
candidate line and complete owner inventory, then compares the combined
covered-state vectors. It grants no deletion credit or uncovered mappings.
Pinned Rustfmt validates the bounded function excerpt in an empty temporary
directory. Module declarations are refused before parsing. Formatter output
does not supply coverage or replace source bytes. This uses the
[Rustfmt parsing contract](https://github.com/rust-lang/rustfmt#running).

These checks have 128 passing Python tests, including failing-before controls
for hidden regressions, ambiguous ownership and malformed source. Independent
reviews found and corrected a partial-owner gap and syntax-recognition gaps
before publication. Fresh producer evidence remains necessary for acceptance.

The added native build test exposed a hardened-mode usability defect.
Two source-free, inert Bubblewrap builds completed but produced different
archives because makepkg records `BUILDDIR` in `.BUILDINFO`. Random private
host paths therefore defeated exact comparison. Builds now retain distinct
physical directories while exposing a stable, collision-free guest build root.
The regression failed before the fix and passed afterward without changing
archive comparison or metadata. A second failing-before test covers custom
cache paths that could otherwise be hidden by that mount.

The native fixture also repeats admission using the verified pairing cache and
then checks that a deliberately failed recipe cannot reuse accepted archives.
It never calls the installation stage. Every local build drive preserved its
own before/after pacman database fingerprint. The final-install fixture checks
that the current hardened profile rejects an install hook before elevation.
Genuine PTY tests verify that hardened review still prompts under `--yes` and
honors refusal; their namespace-root runs verify the ordinary-user boundary.

The latest ordinary checks passed 2,120 library tests, 15 Arch CLI contracts,
18 version tests, all-target Clippy with warnings denied, and 25 coverage-workflow
tests. Six library tests were ignored by default: four existing cases and two
explicit native fixtures. The inert paired-build fixture passed separately on
this Arch host. Historical rollback review remains selected in the existing
network-isolated CI container, where only `/usr/bin/true` receives passwordless
sudo authorization. That container has separate fixture home, cache, data and
configuration directories. No host package installation or removal was used.

A subsequent reader regression reproduced loss of the decoder after a
recoverable I/O error between zstd frames. The reader now models active,
finished and failed states explicitly. Retrying `Interrupted` or `WouldBlock`
at a frame boundary preserves the remaining data; malformed subsequent frames
and the frame budget remain terminal errors. The four reader tests passed
after the boundary retry failed against the old implementation. The isolated
CI build fixture also captures its private build log before removing temporary
state, so unexpected build failures retain their diagnostic evidence.

The hosted fixture exposed a loopback setup denial on Ubuntu. Its CI policy
uses a unique named AppArmor profile with an explicit user-namespace permission,
following [Ubuntu's documented exception](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).
A separate offline loader receives only `MAC_ADMIN` and the securityfs mount;
the fixture receives neither. Cleanup removes the container before unloading
its profile. The fixture keeps both Docker's offline network and Bubblewrap's
private network namespace. No global sysctl or executable attachment changes
are used. Profile syntax and the loader lifecycle are checked locally; actual
policy loading and native execution require the hosted runner.

## Remaining work

- Live searches and several inventory operations still use C libalpm. Move
  individual queries only after matching repository priority, duplicate package
  identities, custom pacman configuration and malformed-metadata behavior.
- The pure Rust database reader retains tolerant manual parsing for metadata
  accepted by native pacman but rejected by the stricter upstream formats.
  Removing this fallback requires a compatibility corpus, not just a crate bump.
- A full privileged transaction and rollback matrix belongs in disposable Arch
  guests. This run did not install/remove host packages or claim those destructive
  operations were exercised end to end.
- Hardened admission rejects classified integration paths. It does not vet
  arbitrary program behavior or provide independent builder provenance. Use
  `allow_aur = false` when official repositories are the required trust boundary.

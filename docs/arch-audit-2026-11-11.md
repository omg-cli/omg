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

A retained provider-loop brace lost its LLVM mapping after fallible validation
was added. Its old count came only from the enclosing block-entry region.
A separate endpoint witness checks the exact loop scope, every compiled copy
and the terminal method and argument regions. It refuses explicit zero counts,
foreign owners and control-flow or call expressions in the data arguments.
The receipt records inherited LLVM paint, not normal arrival at the brace.
It changes no raw counts, ratios or deletion credit.

These checks have 138 passing Python tests, including failing-before controls
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

The full local run passed 2,120 library tests, 15 Arch CLI contracts,
18 version tests, all-target Clippy with warnings denied, and 26 coverage-workflow
tests. Six library tests were ignored by default: four existing cases and two
explicit native fixtures. The inert paired-build fixture passed separately on
this Arch host. Later scoped checks passed 241 AUR and 19 settings tests.
Historical rollback review remains selected in the existing
network-isolated CI container, where only `/usr/bin/true` receives passwordless
sudo authorization. That container has separate fixture home, cache, data and
configuration directories. No host package installation or removal was used.
Its historical review scenarios decline once and separately accept an authored,
source-free recipe that must fail with its log marker before installation.

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

The container also prepares a fresh proc filesystem before dropping to the
fixture user. Docker's hidden proc submounts prevent nested unprivileged proc
mounts; a private-namespace control reproduced that denial and passed after
this preparation. Other container path masks remain in place. The fixture
records mount information and requires both nonroot network-namespace probes.

All 19 selected native cases passed in the latest hosted run, including
historical review acceptance followed by the inert recipe's intentional failure.
The other platform, VM, Docker, Clippy and security jobs also passed. Coverage
remains unverified because successive producers rejected wrapped counts in a
daemon worker and runtime-pin detection before comparison. The retained profiles
and exports remain unchanged.

The initial diagnostic archive contained no raw profile for that function.
The collector now prioritizes profiles containing affected functions and saves
compact coverage maps with original object identities. It retains the same
archive budget and records incomplete capture explicitly. Corrupt report data
must not prevent the remaining evidence from being preserved. Matching LLVM
tools reproduced an executable's export from its compact map without retaining
another executable.

A controlled Rust 1.95/LLVM 22.1.2 probe reproduced an invalid branch count when
continuous profiling retained a worker killed during initialization. Ordinary
exit-flush profiling emitted no profile for that killed child, while retaining
valid coverage from 20 completed workers. The ordinary test producer now uses
exit-flush profiles. Every crash test still runs. The native fixture cases keep
their explicit continuous profiles and remain subject to strict validation.
This changes which interrupted executions contribute coverage; it can reduce
coverage against the existing main baseline. Counter validation, comparison
thresholds and exact-base authority remain unchanged.

The bounded diagnostic collector also retains exact LLVM function-counter
records when whole raw profiles cannot fit. Each projection is linked to its
source identity and content hashes before and after probing. A real mmap
regression showed that counters can change while size and timestamps stay
unchanged. Such changed snapshots are refused. Five actual retained profiles
round-tripped through LLVM with byte-identical projected records.

## Repository and installation batch

This follow-up covers repository policy, authoritative database snapshots, AUR
dependency planning, installation reasons, build evidence, and metadata
publication as one Arch batch. Work remains on the existing local main checkout.
No additional branch or worktree was created, and no host packages were installed
or removed.

Repository `Usage` now controls Sync, Search, Install, and Upgrade independently.
Rust catalogs retain ordered repository candidates until the query selects its
eligible repositories. A missing or corrupt required repository fails instead of
producing a partial update list or false foreign-package classification. Local
queries remain independent of sync availability. Local parsing and derived reads
check source epochs, and v2 caches do not reuse the older completeness claims.
Native queries also require readable regular database files; libalpm's validity
call alone did not establish file existence in the regression.

Native controls confirmed an installation identity bug: `helper>=2` could select
version 2 from a lower-priority repository, then the later bare-name lookup could
select version 1. AUR plans now retain the selected repository, package identity,
and every original relation through the sealed privilege descriptor. Combined
relations select one compatible candidate. The prepared transaction rechecks
identity, eligibility, and all relations before commit. Same-base runtime closure
also handles unique versioned virtual providers. Ambiguous, incompatible, and
ineligible sibling providers fail; make/check inputs remain pre-build requirements.

Installation intent now survives the public, recursive, split-output, parallel,
and elevated paths. Requested packages become explicit. New automatic packages
remain dependencies, and existing explicit packages stay explicit. Reason-only
promotions pass through pre-write audit and completion even when libalpm skips a
same-version reinstall. Cache invalidation and daemon refresh run after failed
attempts, with operation and completion errors retained. Known post-commit audit
or reason failures instruct the caller to inspect installed state before retrying.

A real CLI promotion also exposed unsafe historical install rollback: every
listed package was scheduled for removal, even when it predated the request.
Install history does not establish package pre-existence. Automatic Install
rollback now refuses before consent or mutation; its unproven removal path is
deleted. Known-version Remove/Update restoration remains available. Supporting
safe install reversal requires authoritative provenance and current-state checks;
missing versions must not be interpreted as a new installation.

Built outputs carry the actual build profile and requested-output membership.
A Standard build cannot satisfy a current Hardened policy. Final admission checks
run again after approval, installation queueing, and sudo refresh. Parallel waves
retain each build's evidence. Metadata readers acquire an owned index from one
immutable archive/index/validator generation. Cross-process locks and one durable
manifest publication replace timestamp pairing. Legacy archives are reindexed;
unbound old indexes are not accepted as current. Old generation reclamation is
deferred in this batch.

The batch has failing-before evidence for these findings, independent Rust and
blue-team reviews, and 2,157 passing ordinary library tests. The 205 focused
workflow, source-comparison, and base-authority tests pass. Formatting,
all-target Clippy with warnings denied, binary tests, documentation, and the
checkout CLI build pass on Arch. The all-features lint command requires Debian's
native apt development dependency; this Arch host was not modified to supply it.
Cross-platform CI remains required.

Disposable KVM Arch guests verified the original automatic-dependency failure,
its correction, and real mixed archive transactions. Checks cover dependency
reasons, preservation of explicit packages during upgrades, same-version
promotion, public-request promotion, unrelated state, and reason-only audit.
A self-contained native case joins the isolated CI selection. The prepared guest
backing image remains unchanged. Guest setup and native checks do not reproduce
the hosted Docker AppArmor lifecycle. A real unprivileged CLI-to-sudo drive also preserved unrelated state and
recorded the promotion once. A subsequent install rollback was refused without
changing that package or history. Five read-only checkout CLI checks passed with
an unchanged host pacman fingerprint. Local coverage comparison and fresh hosted
CI are still pending for this batch.

The next verification batch adds repository eligibility, stale-selection,
virtual-provider, incomplete-database and metadata synchronization cases.
The metadata cases exercise real loopback HTTP responses and generation
publication through a private endpoint boundary; the public caller retains the
official AUR URL. A readable corrupt native catalog reproduced a false absent
package result. Loading its lazy package cache before checking native validity
now rejects that catalog, while the native probe preserves valid empty and
nonempty catalogs. The regression and all 40 transaction tests pass.

The consolidated library run passes 2,183 tests with 11 ignored native-only
cases. Independent review approved the source batch. Native descriptor-denial
and self-contained official dependency cases are included in the existing
isolated selection; revised-source guest execution and source-bound coverage
remain pending. Existing native CLI contracts will also run in the Arch guest,
since their explicit Arch prerequisite excludes this Omarchy host.

## Remaining work

- Require fresh producer and exact-base comparison evidence for the retention
  correction. Its controlled failure class is established; the exact processes
  responsible for the earlier CI failures were not identified. An
  [open Rust compiler issue](https://github.com/rust-lang/rust/issues/164153)
  describes underflow during incomplete execution. Exit flushing does not
  guarantee every emitted profile is valid. Any recurrence remains fatal and
  receives the bounded diagnostic capture.
- Live searches and several inventory operations still use C libalpm. Move
  individual queries only after matching repository priority, duplicate package
  identities, custom pacman configuration and malformed-metadata behavior.
- The pure Rust database reader retains tolerant manual parsing for metadata
  accepted by native pacman but rejected by the stricter upstream formats.
  Removing this fallback requires a compatibility corpus, not just a crate bump.
- Extend the disposable-guest transaction matrix beyond the installation and
  reason cases covered here. Removal, rollback, and failure recovery need their
  own real state assertions. No host package mutations are authorized.
- Hardened admission rejects classified integration paths. It does not vet
  arbitrary program behavior or provide independent builder provenance. Use
  `allow_aur = false` when official repositories are the required trust boundary.

## Arch execution and verification follow-up

The follow-up consolidates the owned and supplied-handle ALPM transaction paths
without changing the exported API. Both use the same preparation, question
refusal, intent, commit and audit body. Supplied handles retain caller-owned
repository registration. The pacman configuration parser now owns its current
repository in one section enum, removing inconsistent optional states while
preserving repository order, repeated Usage unions and default All behavior.

A new unprivileged regression reproduced a local-database error being reported
as a successful empty catalog. `Path::exists()` hid a permission error in an
inaccessible ancestor. `try_exists()` now retains the underlying I/O error and
path context; genuinely missing directories keep their existing behavior. The
failing test was committed before the fix. Malformed UTF-8 and missing-name
fixtures reject complete local and sync snapshots even beside healthy entries.
The redundant outer empty-name check was removed after verifying that every
successful typed and manual parser route already requires a name.

The updated local run passed 2,190 library tests, with 11 native-only tests
ignored. All-target Clippy with warnings denied, formatting, 42 CI workflow
tests and the four ALPM pin tests passed. The rebuilt default-feature CLI passed
seven read-only checks against the native host catalogs and preserved their
package database fingerprint. Local test tools remain in the owned task cache.
No host package installation, removal or policy changes were performed.

Expanded disposable native fixtures cover supplied-handle installation,
NEEDED retry, removal, public asynchronous removal, and sealed split-output
admission with requested versus automatic installation reasons. The parallel
AUR fixture retains paired-build and failed-rebuild checks and adds a successful
independent sibling alongside a failed build. Final installation is deliberately
refused through the existing development-mode boundary; it does not claim a
successful parallel-wave installation. Runtime verification of these expanded
native cases is pending at this source checkpoint.

The strict coverage comparison exposed both missing domain execution and a
compiler mapping omission for an eagerly evaluated boolean argument. The new
bounded proof applies only to an already retained pair, requires exact local
callee source, complete singleton owner inventories, matching positive call and
continuation evidence, and absent literal mappings in both regions and segments.
It grants no counter or deletion credit. Raw source line-ending admission keeps
the callee comparison tied to exact Git bytes. Adversarial controls reject zero
or overlapping evidence, ambiguous calls or bindings, oversized UTF-8 input and
contradictory segments. The frozen prior-source replay proves that one pair and
then fails on a separate retained line. A fresh combined-source coverage report
and required hosted CI remain pending; no passing final coverage is claimed.

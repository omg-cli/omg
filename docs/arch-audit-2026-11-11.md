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

## Runtime compatibility follow-up

The follow-up keeps changes in the existing Arch implementation and tests.
Official upstream Git release tags were rechecked on 2026-11-12. The pinned
Rust ALPM package versions still match the latest release tags.

- Version comparison now uses native libalpm when epoch or package-release
  presence differs. The pinned Rust comparator distinguishes an absent epoch
  from explicit zero and orders an absent release below a present release.
  Pacman treats the first pair as equivalent and compares releases only when
  both are present. Direct and cached-update regressions cover hidden upgrades,
  false downgrades, equality and positive epochs. Other ordinary comparisons
  continue through Rust; the existing numeric-overflow fallback remains.
- Strict version parsing rejects NUL before a native comparison. Typed and
  manual database readers share this validation. Both persisted package-cache
  types validate deserialized versions too, while preserving their existing
  serialization format. Regressions reproduced the native CString panic and
  acceptance of malformed versions from an older cache before the fixes.
- HTTPS source prefetching follows installed makepkg's first `::` rename
  separator and literal filename suffix after the last slash. Query strings
  and fragments remain part of unrenamed filenames. This prevents successful
  prefetches from landing under a name an offline makepkg build cannot find.
  HTTPS, destination validation and network-address policy are unchanged.
- Cache cleanup resolves and deduplicates configured directory aliases before
  selecting retained archives. Repeated paths previously counted the same
  newest archive more than once and could delete the retained copy. Package-
  shaped directories and symlinks are excluded. A failed archive unlink leaves
  its detached signature intact. Fixtures use private paths, and the
  environment-dependent configuration fixture enforces unprivileged execution.

The initial grouped regression run reproduced nine failures. Two subsequent
checks reproduced the NUL parsing/comparison failure and the persisted-cache
bypass. Final verification passed 2,267 library tests, with 12 ignored, all 15
`coverage_17` integration tests, and all-target Clippy with warnings denied.
Independent review approved the final five-file code/test diff. These results
do not establish a passing hosted coverage comparison or completion of the
remaining work below.

The update-policy follow-up checks ignored groups on both the installed package
and the selected repository candidate. Native discovery retains the preferred
repository before filtering, so an ignored candidate cannot select a different
version from a lower-priority repository. Private libalpm fixtures first verify
the corresponding native sysupgrade queue without preparing or committing a
transaction, then check OMG's update results and unignored positive controls.

The Rust local database model now retains groups from both official descriptor
formats and the compatibility parser. Its derived cache uses
`local_db_source_v3`; older group-unaware entries cannot suppress installed-group
policy. Invalidation retires both current and legacy names. Four regressions
reproduced the policy failures before the fixes. Verification passed 2,271
library tests, with 12 ignored, all 15 source API integration tests, and
all-target Clippy with warnings denied. Independent review approved the runtime
changes. No package transaction was committed by these fixtures.

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

## Archive admission and completion batch

A harmless native fixture exposed an interpretation boundary: libalpm can use
MTREE to replace the package file list and skip archive payload absent from that
list. A new regression reproduced OMG accepting an ordinary payload with an
empty MTREE before enforcement. This is an admission gap, not an exploit or
severity claim.

The inspector now uses the existing pinned official `alpm-mtree` crate. One
private admission value owns the passive report and expected native inventory.
It bounds metadata decoding, rejects duplicate declarations, and compares the
complete tar and MTREE inventories. Root derives admission from its private
staged archive immediately before native loading, then checks that same loaded
package before insertion. Policy version 4 invalidates older paired-build keys.
The ALPM pin guard now includes the fifth directly used official crate.

Genuine makepkg output determined supported directory, link and escaped-name
representations. A retained harmless fixture covers ordinary and empty paths,
direct backward hard links, symlinks and unusual names. Derived path spellings
and forward links demonstrated why native inventory equality alone cannot
prove extraction. The initial supported subset and its restrictions are
documented in [AUR support](./aur.md).

The batch also gives transaction completion one typed outcome, preserving all
six existing error combinations. Real native regressions cover commit-time file
conflicts and a reason write that changes cache state but fails durably. Metadata
tests cover actual reader I/O errors, preserved generations and snapshots,
panicked tasks and observed cancellation. A missing future build directory is
accepted without being created.

The ordinary library run passed 2,204 tests with 12 tests ignored.
Independent review then found repeated neutral root-directory declarations
bypassing duplicate refusal. Its failing-before regression and passing fix are
retained locally. Added native controls reject an inconsistent sealed handoff
without database, payload or audit changes, and reject a different loaded
package with the same file count. All-target Clippy with warnings denied,
non-Arch all-target compilation, five ALPM pin tests, eight supplemental-producer
tests and 42 existing CI tests pass. The default CLI and daemon build; seven
read-only host CLI checks preserve the native package database fingerprint.

Hosted coverage previously omitted 14 supplemental exact tests and five real
process checks that local verification executed. One shared tracked driver now
supplies them. Independent review caught its missing Docker `NET_ADMIN` grant;
the failure was reproduced with that capability removed before the scoped fix.
The shared driver passes in KVM with the Docker capability bounding set and
preserves its database fingerprint. This does not reproduce Docker's AppArmor,
seccomp, memory or process limits. Final frozen-source coverage and hosted
verification remain open.

## Combined native and public AUR verification

Frozen product commit `64fe5365` passed 3,724 ordinary instrumented tests,
the genuine Node installation case, 20 native Arch cases, 14 supplemental
CLI cases and five CLI/daemon process checks. A storage interruption stopped
two ordinary cases; those exact cases were rerun successfully. The union
receipt inventories all 3,724 distinct passing identities. It does not claim
that the interrupted component met its storage budget.

A real `omg install --yes` invocation under an ordinary guest account also
completed attended Hardened review, paired makepkg builds and real sudo/root
transactions. The harmless app's build reads its installed dependency payload.
Fresh native queries verified exact package identities, file lists and durable
Requested/Automatic reasons. Further real invocations promoted the dependency
to Explicit and preserved that reason on a later app installation. Payload
bytes, modes, root ownership, audit order, unrelated package records and released
transaction locks were checked. This does not establish a new Automatic-intent
handoff for an already satisfied dependency, historical rollback, or immediate
sudo-refresh attribution. The guest had no external network route; real Git
repositories and a private TLS service supplied the fixed AUR hostname.

The warm coverage target contained obsolete executables. Export now selects
exactly the 98 current Nextest harnesses and the two actual Cargo CLI/daemon
artifacts. Independent review verified those 100 physical objects, complete
profile inventories and retained tar bytes. A local validator initially refused
passing native parent/child logs because it expected one total libtest summary.
Recovery checked every summary and preserved the original failure receipt;
the actual native tests were not rerun to manufacture passing evidence.

The frozen export combines 8,909 ordinary profiles, 283 native/supplemental
profiles and eight profiles from the real public AUR wave. Source, executable
and input-profile hashes remain bound to `64fe5365`. Strict comparison still
fails. The diagnostic inventories eight affected files, including new test
fixture error projections and ambiguous retained-source correspondence. No
counter, threshold or deletion/fold acceptance was changed.

The subsequent inventory refinement stores resolved hard-link sizes while
preserving their distinct origin, so chains remain refused without a second
fallible target lookup. Native mode/size conversion has safe scalar refusal
tests alongside the real loaded-package checks. Fixed fixture setup fails with
descriptive expectations; actual operation-error assertions remain intact.
The corrected refinement passes 2,206 library tests with 12 ignored, the native
transaction parent and its real child cases, all-target Clippy with warnings
denied, CLI/daemon builds and documentation generation. The optional bounded
coverage diagnostic passes 192 tests and leaves the strict verdict unchanged.
This newer Rust source has not yet received a fresh full instrumented export.

The normal native target budget is now 52 GiB, with a 20 GiB host reserve.
Its earlier 2 GiB growth monitor stopped Clippy after the passing library run.
The admitted continuation passed without rerunning the library suite. Coverage
retains its separate 40 GiB target budget. Unresolved linker/debug evidence and
the current QEMU backing images remain preserved. Host package state and
privilege policy were not changed.

## November 12 resource and integration checkpoint

The next Arch batch keeps parsed `.SRCINFO` owned by the reviewed source snapshot
through dependency planning, installed-state rechecks, source extraction and
offline builds. Public path APIs retain their signatures through a shared bounded
regular-file reader. Git mirrors and historical rollback share bounded capture,
staging observation, deadlines and process-group cleanup. Capability retention and
approval formatting now check byte budgets before encoding or extending buffers.
That product batch passed 2,232 library tests, 15 source API tests, lint, builds
and docs checks.

The production CLI completed a genuine AUR install, update and historical rollback
in a disposable Arch guest. A separate current-build scenario observed a sealed
Automatic request for a previously Explicit split sibling, preserved its Explicit
reason, captured immediate credential refresh before handoff, and observed two
native makepkg processes overlap before one successful update transaction.
Payloads, inventories, ownership, reasons, unrelated records, locks and cleanup
were checked. These are scoped offline KVM observations, not Docker-policy parity
or a claim that arbitrary AUR programs are safe.

Hosted verification then exposed incomplete native fixture prerequisites. The
corrected image supplies Git, Make, jq and diffutils, and reports every missing
tool under the actual ordinary-user PATH before running tests. All 14 supplemental
tests and five CLI/daemon process checks subsequently passed in hosted CI, and
the resulting coverage counters passed strict validation. The remaining stale
history fixture was corrected to the bounded Git contract; its actual native
review case passed locally with its original approval and failure assertions.

A combined independent review covered all 49 prepared source items in the PR.
It found a Hardened admission gap in omitted local and runtime loader locations.
Inert archive tests reproduced acceptance under both omitted systemd generator
roots and 19 related loader/configuration aliases. Inspection policy 6 groups the
documented privileged prefixes and exact configuration files in explicit tables.
Focused tests now refuse those paths while retaining ordinary local application
paths and adjacent names. No generator payload was installed or executed.

At published head `9426e52c`, Main CI, Security Audit, Secret Scanning, CodeQL,
Docker E2E and the complete hosted coverage producer passed. All seven added-file
coverage requirements passed. The exact-base comparison still rejects ambiguous
source correspondence in the ALPM transaction refactor. This remains an open
gate, and the PR is not merge-ready. Coverage criteria are unchanged.

The next local batch also corrected two transaction failure fixtures. Their
release-less versions made libalpm index a dashed package name incorrectly.
Stronger assertions reproduced “package not found” instead of the intended
conflict and missing-dependency paths. Release-bearing fixture versions now reach
native conflict preparation and the fail-closed refusal to drop an unresolved
package. The latter test also checks that no package was installed and no lock
remains. All six failure tests passed against private databases and offline
file mirrors. All 37 artifact-inspector tests and all-target Clippy with warnings
denied passed. Independent review approved the two-file test diff. These local
checks do not establish a fresh hosted coverage verdict.

The local checkout stays on `main`; the approved remote PR branch is the only
publication target.

## Relation, catalog identity and policy compatibility batch

A further boundary review found raw dependency and provision strings reaching
native `CString` conversion without the package-version NUL guard. Three tests
reproduced native `NulError` panics. The existing relation helpers now refuse NUL
in either operand before parsing, comparison or unconstrained early returns.
The shared health-relation parser rejects it before orphan and doctor matching.
Healthy package and soname relation semantics remain covered.

Sync catalogs now require one package directory whose native name and normalized
version agree with the parsed metadata. Invalid names, nested paths and duplicate
package identities refuse the catalog instead of overwriting a query candidate.
A review found and reproduced a nested-path bypass before the final guard.
Valid release spelling that normalizes numerically remains accepted. Active sync
caches use `sync_db_source_v3`; old v2 caches cannot bypass identity validation.
Invalidation removes both generations. Standalone version tests retain optional
release semantics, while release-less sync identities are refused because native
ALPM cannot represent them under the advertised package name.

IgnorePkg, IgnoreGroup and HoldPkg now share pacman's POSIX pattern grammar.
The small existing-module matcher owns its C strings and calls native `fnmatch`
with flags zero. It preserves literal braces, bracket behavior and the matched
HoldPkg diagnostic. NUL configuration patterns return an error. The unused
direct globset dependency was removed without changing other dependency versions.
AUR update discovery now applies installed IgnoreGroup membership from one local
snapshot as well as IgnorePkg.

The failing-before wave reproduced eight failing regressions. Final local verification
passed 2,279 library tests with 12 ignored, all 15 source integration tests, all
six transaction failure tests, all-target Clippy with warnings denied, and the
CLI/daemon build. Independent review approved the final source diff. The built
CLI passed version/help checks and read-only `info pacman` and `list` operations
against this Arch host with isolated OMG state and the daemon disabled. No host
packages were installed or removed.

This runtime proof does not close the hosted exact-base coverage comparison.
The preceding published head `e59d3eb3` passed its instrumented producer but the
comparison still rejected ALPM source correspondence at base line 523 versus
head line 587. Current hosted results remain recorded on PR #1057.


## Official schema and private staging batch

Local database parsing now uses the official Rust `DbDescFile` schema dispatch
and its V2-to-V1 conversion, with one projection into OMG's package record.
The typed V1 fallback remains necessary when a description contains the literal
text `%XDATA%`: upstream schema detection treats that text as a V2 hint. A
regression caught a changed installation timestamp before publication. Tests
cover both wire schemas, projected metadata, installation reasons and invalid
NUL-bearing versions.

Cache cleanup now distinguishes a missing directory from an inaccessible one.
The failing-before test returned success and deleted an old archive and its
signature despite another configured cache being unreadable. Canonicalization
now preserves the permission error and aborts before removing any archive.

The native test batch exposed another dependency on process-wide state. Vendored
libalpm temporarily sets `umask(0000)` while creating directories. A child-only
control reproduced an outer archive with mode `0666` and its directory with mode
`0777`. The strict admission check correctly refused that fixture. Positive
archive fixtures now request private permissions at creation; negative permission
checks remain intact.

The same review found production staging directories and copied files relying
on umask. Privileged staging now requests `0700` directories and creates archives
and detached signatures with `0600` and exclusive creation. Scoped PGP homes,
exported key bundles, rollback checkouts and metadata generations also request
private permissions at creation. Existing tests failed under a child process
with umask zero before these fixes, then passed. Arch revalidates staged archive
permissions before loading, so the demonstrated old staging behavior fails
closed; this evidence does not establish arbitrary package installation.

Transaction failure tests now cover both caller-supplied and internally owned
native handles, using private databases and offline mirrors. A temporary fault
control removed the native preparation error translation and made both
missing-dependency cases fail with the raw native error. Restoring the production
translation restores the intended refusal. Fresh native observers verify exact
package absence and lock release. The Git helper fixture also exercises actual
fallback termination and reaps its owned inert child.

Local verification passed 2,282 library tests with 12 ignored, all 15 source
integration tests, all nine transaction failure tests and five explicit
umask-zero controls. All-target Clippy with warnings denied, the CLI/daemon build,
version/help checks and read-only host `info pacman` and `list` checks passed.
Independent reviews approved the runtime changes and the coverage checker.

The existing coverage checker now proves a narrow transparent function
extraction and direct `map_err` callback correspondence while retaining complete
compiled-copy obligations. It validates full raw Rust symbol contexts, scoped
capture construction and child geometry. Unsupported macros, attributes and
ambiguous owners are refused. Its 212 tests pass. Replaying the unchanged hosted
`3461d0d4` evidence clears the former correspondence refusal and stops at a real
uncovered cache branch. This replay is not a current full coverage verdict.
Counters, reports, instrumentation settings, exclusions and thresholds are
unchanged. Fresh hosted producer and exact-base comparison results remain
required before merging.

The next security pass must examine general cache-directory creation and
package-base and metadata lock inode handling. The private staging fixes do not
claim those separate boundaries are complete.


## Metadata ownership and lock inode batch

Five private-fixture regressions reproduced metadata cleanup during an active
publication lease, acceptance of package-base and publication lock symlinks,
and fresh coordination files with mode `0644` instead of `0600`.

Metadata locations now carry their build directory explicitly and derive `_meta`
from it. The owned metadata guard retains both publication coordination and the
shared build lifecycle lease. It acquires lifecycle ownership before metadata
creation and keeps both descriptors through the existing blocking publication
workers. Cleanup continues to request exclusive lifecycle ownership without
waiting. A cancelled awaiting task cannot release the worker's cleanup protection
early. Tests observe cleanup refusal while the detached worker is active,
publication completion, then successful cleanup after ownership is released.

Package-base and publication files now refuse symlinks, multiply linked or
nonregular inodes, unexpected effective-user ownership and group/other writable
permissions. Fresh files request `0600`. Existing owner-held `0644` locks remain
accepted; this batch does not silently change their permissions. The existing
lifecycle opener retains its separate original-user ownership behavior. General
cache-parent ownership and creation policy remain pending.

Generic metadata fixtures now use explicit private `owner/aur/_meta` locations.
No implementation infers a build root from an arbitrary temporary directory's
parent. Missing metadata reads and disabled synchronization retain their early
returns without creating cache or coordination paths.

Verification passed 2,286 library tests with 12 ignored, all 15 source integration
tests, all nine transaction failure tests, three umask-zero lock controls,
all-target Clippy with warnings denied, and the CLI/daemon build. Independent
correctness and security review approved the runtime diff. The fresh CLI passed
version/help and read-only host `info pacman` and `list` checks with private OMG
state and the daemon disabled.

The published `d4ce2e6a` coverage producer passes, but its exact-base comparison
remains open. Fresh evidence identifies a real lost hit in mirror configuration,
additional uncovered branches and several incorrect source correspondences.
Those findings require explicit tests or mapping proof; passing the lock batch
does not close that gate.


A follow-up behavior batch covers a configured repository absent from a supplied
native handle without registering an extra database. It uses only private
`file://` mirror configuration and checks the registered repository's expanded
server. Additional sync-archive cases refuse invalid names inside an otherwise
flat entry and require the repository and entry in the error. The owned-child
fixture now reads its proc identity before writing the observation file.
All 578 package-manager tests passed with 11 ignored, as did all-target Clippy
with warnings denied. Independent review approved these test changes. These are
passing behavior cases for expected production behavior, not reproduced runtime
bugs or a fresh complete coverage verdict.


## November 13: Omarchy checkout and advisory verification

The Omarchy preflight treated the user-owned data checkout as a trusted executable path. The fix accepts that checkout while retaining fixed system executable resolution. Regression tests place an executable sentinel in the checkout and require it never to run. Empty checkout and migration-state variables fail before scanning.

The follow-up batch adds real filesystem, child-process, authorization-worker and terminal-input failure tests. All 41 Omarchy tests pass. The full library suite passes 2,351 tests with 13 ignored. All-target Clippy with warnings denied passes after converting one test-only match to let-else. These tests do not establish exhaustive OS-error coverage.

The coverage checker now binds a qualified literal-only macro site to its function parameters, preceding visible statements, control context and imports, including visible extern-crate aliases. Changed aliases and invalid compiler-copy evidence refuse proof. All 257 comparison tests and six external regression tests pass. The frozen earlier comparison progresses past config.rs but still refuses the cross-owner predicate extraction in style.rs. Acceptance thresholds, counter evidence and compiler-copy matching remain unchanged.

Hosted coverage production passed on bf6c83f8. Its comparison reports incomplete coverage in the new Omarchy module: 1,877 of 1,972 summary lines. Hosted Arch QEMU also exposed a stale fixture destination after the production client moved to Cloudflare. The fixture now binds isolated DNS and TLS to that fixed destination and serves the exact snapshot envelope. It tests bad payload hashes, stale or future timestamps, reversed timestamps and strict JSON field types. Seventeen focused fixture checks pass.

A disposable KVM rerun used the exact binary pair and archive from the failed hosted run. TLS refusal, snapshot rejection, direct and daemon findings, and evidence replay pass. The native package database and prepared guest image remain unchanged. This local rerun does not replace the pending hosted verdict or instrumented coverage acceptance.

The tested PR release-profile pair is installed in the user's local binary directory. A real read-only host audit validates the fresh production Arch snapshot and preserves the package database. No host package update or service change was performed. Historical CVE archive verification, AUR applicability and operation-level advisory admission remain incomplete.


## November 13: advisory coverage and fresh prepared admission

A real CLI regression used a private installed-package database containing one unmapped package. The preceding installed build printed an unqualified zero-findings result. Two JSON contract tests also failed before implementation. Reports now retain Unknown coverage and Possible findings separately from applicable matches. The CLI, daemon, TUI and SBOM preserve that distinction; automatic remediation excludes Possible matches. IPC protocol 5 rejects older binary frames before decoding, with direct audit fallback available.

The explicit `fresh_snapshot` policy obtains one validated Arch snapshot for the actual prepared transaction and rechecks package identities, archive hashes, policy, AUR profile, invoking identity and snapshot age before commit. Repository coordinates require explicit operator scope. Unknown local/AUR coverage requires an attended privileged confirmation for the full prepared batch digest; `--yes` cannot grant it. The scoped cancellation owner releases the native transaction before restoring its signal dispositions on refusal. Existing missing-policy offline behavior and legacy explicit-policy evidence requirements remain distinct.

Final source-bound verification passed 2,384 library tests with 13 ignored, default/backend-free/Debian-indexing all-target Clippy with warnings denied, and normal CLI/daemon builds. Eight legacy policy tests now call production policy or service paths; three duplicate test-only implementations were removed. Independent Rust, policy, wire-codec and comment reviews approved the scoped changes.

The actual built CLI and an independently owned production daemon both reported the private unmapped inventory honestly. A daemon request counter proved the CLI reached that daemon; the fixture database remained unchanged and the owned process and socket were cleaned up. The same binary pair passed all seven Omarchy guest cases, including the user-checkout sentinel and exact helper traces, with no external AUR helper execution.

Sixteen additional disposable Arch guest cases passed with real native transactions against private inert package roots. They cover offline Optional success, one-snapshot whole-operation success, vulnerable prepared dependency refusal, empty/undeclared repository scope, unattended local refusal, real sudo PTY acceptance/wrong answer/decline/Ctrl-C, changed policy after confirmation, payload hash and timestamp rejection, and untrusted TLS refusal. Every refused operation left its private database unchanged and released its lock; successful controls committed their inert payloads. The real guest database and prepared disks remained unchanged, and the VM shut down cleanly. Initial driver setup failures are retained as failures, including incomplete package fixtures; they are not counted as production regressions or passing cases.

Local proof receipts are `arch-security17-green9-receipt.json`, `advisory-coverage17-green9/receipt.json`, `omarchy17-cli-green9/receipt.json` and `fresh17-cli5/receipt.json`. The normal debug CLI SHA-256 is `78326b05e4ead0f0219cc57145e2274d095b1d29ea6f622053916e416916d493`; the daemon is `b471b34269ad61684f4bbaf8d59bb6531cabb9d68e1307f7648ab01b793b1606`. These are local source-bound product checks, not hosted CI or instrumented-coverage verdicts.

The published preceding head `935cee80` passed its main hosted CI, including distro/QEMU lanes, but its coverage comparison still refused incomplete Omarchy coverage. No coverage thresholds, exclusions, counter evidence or acceptance rules changed. Full CVE baseline reconciliation and AUR applicability mapping remain incomplete. The new admission checks do not prove arbitrary package behavior safe, historical installed origin, sealed AUR build provenance, or cancellation behavior outside their scoped admission window. Numeric process-group ownership and general cache-parent ownership remain audit work.


### Hosted fixture corrections and cloned-guest health

The `d6e59016` hosted run exposed six integration-test contracts missed by the library-only execution: complete-scan wording, an OSV fixture's unspecified origin, and a policy test without a private writable audit directory. The corrective batch preserves the original failure, pagination, cache, inventory and file-byte assertions. The explicit OSV fixture now declares DistributionPackage origin and checks assessed scope and provenance. Seven scoped real tests pass, including the hermetic CLI inventory and Debian-indexing cases; default/backend-free/Debian-indexing all-target Clippy and the CLI/daemon build pass. Production Rust policy code is byte-identical before its test module.

A separate Ubuntu QEMU trial completed its remove operation but failed final health admission. Exported boot evidence shows the disabled `|/bin/false` crash handler before that operation, in the same boot; it does not establish which actor disabled it. Every successful cloned boot now reapplies the existing staged vendor collector helper before measurement. Failed boot or activation stops the workload. Strict post-workload health admission remains unchanged. Two new command-order tests failed before the fix; all 11 transaction tests and five provisioning tests pass, and health tests pass with one existing skip. Independent review approved both the fixture and clone changes.

A disposable Arch KVM control reproduced disabled-handler refusal, ran the real vendor helper twice with identical configuration and capability evidence, and passed strict boot/serial health validation. Its prepared disks remained unchanged and it shut down cleanly. This verifies the helper lifecycle correction, not a full Ubuntu transaction replay; fresh hosted verification remains necessary.

The official November 13 midnight CVE archive was also downloaded and matched its published 661,998,144-byte size and SHA-256. The unchanged production parser accepted 43,080 records before its 1 MiB record bound refused further processing; exhaustion remains false. Separate bounded metadata enumeration found 424,926 CVE members, including ten larger than that bound, with a maximum declared size of 2,402,038 bytes. No CVE member triggered encryption or compression-ratio bounds. Metadata enumeration is not full payload validation. Production limits and Cloudflare data remain unchanged; no import or server archive certification follows from this local evidence.


### Empty inventory and complete local CVE parsing

Hosted coverage found that six empty-inventory CLI operations still fetched the Arch
advisory snapshot. A loopback failure test reproduced the unnecessary request before the
fix. Empty Review now returns an empty assessment without source I/O. Native audit still
performs a second inventory read and propagates inventory errors or changes. Admission
and nonempty Review retain their evidence requirements.

The source-bound checks pass 2,386 library tests with 13 ignored, the hermetic CLI
inventory, three feature configurations of all-target Clippy with warnings denied, and
normal CLI/daemon builds. A disposable Arch guest passes the existing 16 admission
cases, six exact empty-offline commands, and 14 additional controls. Empty commands make
no TCP connection or HTTP request; nonempty Unknown inventory still refuses an
unavailable advisory source. Invalid inventory and recovery controls retain their real
native database checks. The first guest attempt failed because its new harness
incorrectly expected exit zero from an empty `pacman -Q`; that failure is retained, and
the corrected helper requires the exact empty tuple of exit one and empty stdout/stderr.

Five failing service tests reproduced the CVE size limit through archive scanning, delta
fetching, parsing and the actual local Worker entrypoint. CVE raw records now have a
separate 3 MiB bound. The complete encoded 4 MiB request limit, eight-record operator
limit, 16 MiB Arch/KEV feed limit and archive safeguards remain unchanged. All 39 service
tests pass. A structured 2,402,038-byte record roundtrips byte-for-byte through local
R2; its D1 metadata occupies 344 scalar bytes. This test does not measure production
isolate CPU or memory.

The production scanner then exhaustively parsed the retained official archive: 424,926
distinct CVEs, comprising 405,756 PUBLISHED and 19,170 REJECTED records, without
duplicates or unsupported exclusions. The exact raw-record hash manifest is 42,343,545
bytes with SHA-256 `5ba309e089829386cfe73115c1b9b64cb5a1cda1267fac50c3144a34e1b6f1cf`.
The input hash and original failure evidence remain intact. The private scan harness
received a retry-guard edit after launch; the exact original harness and preparation
file were recovered against their previously frozen hashes, and the event is recorded
separately. Production parser and dependency hashes remained unchanged throughout the
run. This is local parsing evidence, not immutable full-harness execution evidence, a
Cloudflare import, server archive certification or package applicability proof.

The Arch QEMU oracle also required the old finding-line suffix. Its regression replays
actual captured installed-inventory output before the correction. Live direct and daemon
callers now require both the exact Possible-match marker and an explicit scope warning
with zero assessed packages and a positive Unknown count. Applicable synthetic unit
controls retain their separate strict contract. All 17 focused oracle and evidence tests
pass, including malformed output, fabricated scores, wrong identities and missing scope
warnings.


### Omarchy helper runtime and migration tree

A subsequent user-triggered update passed the original preflight fix but failed
Omarchy's newer source-root guard after pruning and snapshot stages. OMG selected
trusted packaged helpers while passing the caller's checkout in `OMARCHY_PATH`.
Two actual child-environment tests failed before the fix, including the PTY
coordinator path. The reported host log is retained privately; the agent did not
rerun the host update.

One private runtime now derives its root from the selected trusted migration
helper. Packaged `/usr/bin` helpers select `/usr/share/omarchy`; compatible trusted
checkout helpers select their own canonical root. Child environments, cleanup and
both migration preflights use that same root and resolved migration-state path.
Directory ownership and selected helper layout are rechecked after package
updates. Empty explicit paths still fail, and user-owned checkout programs never
execute. Migration checks inspect the selected runtime rather than an unrelated
checkout.

Independent review found that early validation also made optional helper layout
errors fatal. A protected guest reproduced that failure with a trusted helper
from a different root. Optional snapshot, shell-restart and mise errors now reach
the existing warning policy; confirmation remains skipped under `--yes`. Strict
validation still applies when a helper actually runs. Foreign fixture helpers
write an execution marker before their vendor guard, and the guest requires that
marker to remain absent.

Final verification passes 2,392 library tests with 13 ignored, all 55 Omarchy
tests, the hermetic CLI inventory, three all-target Clippy configurations with
warnings denied, and normal CLI/daemon builds. This final native wave inherited
`no_new_privs`. All seven actual protected Omarchy guest scenarios pass, including
the inverse migration-tree controls and optional foreign-helper refusal. The real
guest database and prepared disks remain unchanged, locks are released, and the
VM shuts down cleanly. These are local product results, not a hosted CI or
instrumented-coverage verdict.


### Native Omarchy package stages and signed refusal controls

The package stages now use OMG's own Rust/ALPM path instead of Omarchy's package
helpers. A closed elevated protocol selects cache pruning, signing-key refresh,
repository upgrade or orphan removal. Real sudo launches the same executable in
a system scope so a user-manager restart does not kill the package worker.
Native repository reads and the ALPM worker now configure the same GPGDir as
transactions. Root/database/keyring paths reject NUL values before C-string
conversion, and unsupported non-UTF-8 paths fail without opening lossy aliases.

The signed-guest tests found a crash during keyring preparation when a repository
record omitted PACKAGER. The crash left a database lock. Guest crash metadata
confirmed SIGSEGV, but no core was stored, so no exact stack frame is claimed.
The official Rust repository descriptor requires PACKAGER, and libalpm's keyring
preparation duplicates that field. Prepared repository records now reject its
absence before commit. The import callback also avoids the binding's UID getter,
which assumes a non-null string, and records refused signing-key imports so a
generic native error cannot hide the trust decision.

A second control found that the vendor's absolute overwrite glob failed under a
non-default RootDir. The native pattern is now relative to the package root and
remains restricted to `usr/share/omarchy`. Signed collisions inside that subtree
can be replaced; outside collisions are refused. Earlier signed keyring commits
remain accounted for when the subsequent repository transaction fails.

Doctor's local database check now uses the validated Rust snapshot and offline
libalpm dependency/conflict checks, plus duplicate non-directory ownership
checks. It does not invoke pacman, register sync databases, start transactions,
run hooks or write the database. Cache pruning retains two distinct versions per
canonical cache directory and architecture, including their archive copies and
signatures.

The current local verification passes 2,402 library tests with 13 ignored, all
three all-target Clippy configurations with warnings denied, and normal CLI and
daemon builds. A signed disposable guest completes the full coordinated update
and all six controls: invalid database signature, unknown package signer, active
database lock, allowed overwrite, refused outside overwrite and missing PACKAGER.
The same native worker survives a real user-manager reexecution while a package
response is held. AUR RPC occurs only after post-update hooks. Forbidden package
helper execution remains zero, the real guest database and prepared images remain
unchanged, and shutdown is clean.

These are source-bound local results. Supplemental CLI coverage now uses the
existing KVM runner with real sudo and systemd; package-helper sentinels refuse
execution. All seven migrated Omarchy scenarios pass locally, including signed
package payload, install-reason, orphan and cache assertions for both successful
updates. The workflow and transport checks pass. Full hosted instrumented
execution, coverage comparison and optimized installation acceptance remain pending. New
trust bootstrap is unsupported, and controlled helper fixtures do not certify all
vendor migrations or maintainer hooks. No host system update was performed.

### Native fixture and Omarchy state verification

The native dependency-reason fixture exposed a positive repository record missing
`PACKAGER`. Positive archive, repository and shared ALPM fixture builders now
supply consistent maintainer metadata. The deliberately missing-metadata refusal
remains unchanged. A prepared-admission regression failed with the same metadata
error before correction; 42 related repository tests then passed.

Omarchy package stages carry their native operation directly. Reboot inspection
uses explicit filesystem, process and session inputs, with private-file tests for
kernel ownership, reboot markers, replaced Hyprland executables, UID filtering,
invalid releases and disappearing process data. The exact descriptor handoff
callback is shared with its tests; parent coordination descriptors remain private.
All four PTY fixture users now use the production atomic close-on-exec allocator.
A deterministic regression reproduced terminal EOF being held open by an unrelated
child, then passed while that child remained alive. Its timeout was unchanged.

The local instrumented library run passed 2,407 tests with 13 ignored. After a
closure-borrow lint cleanup, the same normal library suite, all three feature lint
lanes and both normal binaries passed. The instrumented run used CI's pinned
coverage tool and settings in a separately budgeted target. Full native guest
fixture verification and the hosted coverage comparison remain pending; coverage
thresholds, exclusions and counters were not relaxed. The existing verified
optimized preview predates this refactor and remains separate from final build
acceptance.

The d4726393 batch passed the current 22 native library fixtures in a disposable
Arch KVM guest, including the repaired repository metadata fixture. The same
commit passed the six-artifact supplemental producer, its 14 selected tests, and
all seven original Omarchy scenarios. The merged local library and guest report
reached 227/229 Omarchy functions and 3317/3441 lines; this is progress, not a
passing source coverage comparison.

A normal optimized CLI and daemon pair from d4726393 passed a separate disposable
guest proof of a full signed native update, continuity through user-manager
reexecution, and all six existing refusal controls. The verified local bundle is
`omg-pr1057-d4726393-x86_64-arch.tar.gz`, SHA-256
`0d72ecfffe96f534c9f4b156fdd6a8276f02c4b69970d0fa6181435345b7f2c9`.
Hosted coverage and the PR checks remain pending. The host installation was not
changed.

The supplemental fixture now declares scenarios with named expected status,
helper trace, optional scene, missing helper, and committed native state. The
producer derives its execution list from that declaration. Three appended cases
exercise missing and unsupported snapshot helpers and a missing required
development helper. The original seven scenarios and all six artifact roles
remain selected. Their real guest execution is required before claiming the
expanded fixture has passed.

The attended terminal fixture exposed a real relay defect. After a successful
native update, the coordinator waited for reboot confirmation while the outer
CLI buffered the prompt because it had no trailing newline. The focused
`partial_prompt_is_visible_before_the_terminal_requires_input` regression first
failed with `partial prompt was not visible before input: Err(Elapsed(()))`.
Flushing each forwarded terminal packet made the same test pass in 0.01 seconds.
The completed-coordinator drain also flushes its final packet. Existing output
failure and cancellation handling remains in place.

The batch passed 2408 library tests with 13 existing ignores, all-target Clippy
with warnings denied for default, minimal and Debian pure features, and the
normal CLI/daemon build. The exact committed fix then passed the protected six-artifact guest producer,
its 14 selected tests, and all 13 Omarchy scenarios. Actual terminal receipts
recorded the reboot prompt, decline/accept response, window resize and expected
CLI status, including the failing inert reboot helper. The fresh merged local
report reached 232/234 Omarchy functions and 3394/3500 lines. Strict source
coverage comparison still needs work; no threshold or exclusion was changed.

The normal optimized pair from 0584c726 also passed the full signed update,
user-manager reexecution, six refusal/collision controls, and all 13 Omarchy
scenarios in a separate disposable guest. Its three attended outcomes passed
with the same real terminal protocol. The replacement local bundle is
`omg-pr1057-0584c726-x86_64-arch.tar.gz`, SHA-256
`b200517913e38b92cfb0d9632297beff1fe59f891fbb96c6097a4e067fa9e30a`.
This replaces the d4726393 candidate, which predates the prompt-flush fix. The
host installation remains unchanged, and hosted comparison is still pending.

The next supplemental guest batch passed all 15 Omarchy scenarios, including
actual authorization refresh and refusal after the unchanged 60-second interval.
Root-owned sudo logs bind each initial authorization and timed refresh to the
invoking user, root target, command, timestamp and exact log digest. The denied
control records an explicit permission refusal and the CLI warning; it does not
substitute a successful helper. Each scenario retains its native package-state,
helper-trace and cleanup checks. The sudo policy changes exist only in the
disposable guest. All original scenario deadlines and the production refresh
interval are unchanged.

The producer and exporter checks passed 29 and 16 tests respectively. The merged
local Omarchy report reached 233/234 functions and 3407/3500 lines. The latest
completed hosted Arch, workflow and full instrumented jobs passed; strict added
file coverage comparison remains the outstanding gate. No coverage acceptance
rule was relaxed. These fixture-only changes preserve every Rust and Cargo input
of the verified 0584c726 install bundle.

The missing-runtime-directory batch passed all 17 Omarchy guest scenarios. With
`XDG_RUNTIME_DIR` absent, the actual CLI completed the signed update using a
private `/tmp` coordination lock. A foreign-owned writable lock was refused
without changing its inode, ownership, mode, payload or the preceding transcript.
The fixture checks released leases through a read-only descriptor, preserving
Linux sticky-directory protections. The producer and exporter checks passed 30
and 16 tests. The current merged local report reaches all 234 instrumented
Omarchy functions and 3408/3500 lines; this does not establish full branch or
line coverage, and strict source comparison remains open. Rust and Cargo inputs
still match the verified 0584c726 bundle.

The cancellation batch exposed a production failure through the actual CLI,
which the library-only terminal tests did not reproduce. Closing its output
pipe after a helper and descendant became ready terminated the CLI with
`SIGPIPE`: the regression reported `Controlled CLI returned -13; expected a
handled failure (1)`. CLI startup deliberately restores Unix pipe termination.
The updater now registers pipe handling with its existing interruption streams,
allowing its write-error path to stop and drain the coordinator before reporting
failure. Ordinary commands retain their existing startup pipe behavior.

The two real cancellation controls passed in a narrow disposable Arch guest
probe in 18.671 seconds. They observed helper process identities before the
signal or pipe closure, checked their disappearance after cleanup, and confirmed
that an unrelated process survived. Installed payload and local database hashes
remained unchanged, the cache retained its two intended versions, and the lock
was released. No profiles from this exploratory probe were imported. The full
six-role producer, 19 scenarios, broad Rust checks and replacement release build
still require verification. The prior optimized bundle predates this fix.

Native fixture verification now distinguishes initial, cache-pruned and completed
states. Every declared scenario verifies its expected package state, including
refused or interrupted updates. All original scenarios, coverage thresholds,
source checks and artifact roles remain required. Producer tests passed 32 cases;
45 ordinary-user exporter tests passed, and the root-only exporter case passed
inside the disposable guest. The current hosted instrumented run passed, while
its strict added-file coverage comparison still fails for the Omarchy module.

The complete 0fa345e7 cancellation batch passed normal and instrumented library
runs (2408 tests each, 13 existing ignores), all-target Clippy with warnings denied
for default, minimal and Debian pure features, normal CLI/daemon builds, and the
optimized release build. The protected six-role producer passed its 14 selected
tests and all 19 Omarchy scenarios in 217.101 seconds, importing 309 genuine
profiles only after validation and clean shutdown. Every scenario passed its
expected native package-state check. The merged report reaches 234/234 Omarchy
functions and 3417/3501 summary lines, with 65 uncovered mapped lines. Strict
source coverage comparison remains open; neither metric is complete coverage.

The optimized pair independently passed the full signed native update,
user-manager reexecution, six refusal controls, and all 19 scenarios in 171.892
seconds. Both cancellation receipts confirm the expected handled error, cleanup
of the observed helper and descendant, survival of an unrelated process, and
unchanged installed payload/database. Both guests preserved their pinned inputs,
real system package databases and exact binary identities and shut down cleanly.
The replacement local bundle is `omg-pr1057-0fa345e7-x86_64-arch.tar.gz`, SHA-256
`4017d12f9e7e638ecca7d06a64fad0061e1d5429578ab132021e2e2d94826f27`.
Its embedded receipt identifies the exact source, binary hashes and guest proof.
It supersedes the 0584c726 candidate for the pipe-disconnection fix; the host
installation remains unchanged. Exact-head hosted CI and coverage comparison
still require acceptance before merging.

The next native metadata batch reproduced two fallback inconsistencies against
private Rust-parsed package records. All three native info paths discarded
comparison operators and version values from dependencies, including distinct
`libfoo.so=2-64` and `libfoo.so=3-64` requirements. The direct sync query also
reported `Some(0)` for a declared 4096-byte archive before a transaction was
prepared; the other native query correctly reported `Some(4096)`. Both failures
were observed before changing the production getters.

Native info now serializes complete ALPM dependencies and reports the declared
archive size rather than transaction-specific download state. Regression checks
compare local, direct-sync and shared-handle results with the Rust parser,
covering every comparison operator, an epoch/release and distinct soname values.
The two regressions pass, as do 2410 library tests (13 existing ignores), all three
feature Clippy lanes and normal CLI/daemon builds. Five additional fatal vendor
lifecycle controls have passing producer/export-boundary tests; their actual
guest execution, the expanded 24-scenario coverage producer and a new optimized
pair still require verification before this batch is published.

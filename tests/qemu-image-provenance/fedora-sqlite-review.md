# Fedora 44 SQLite baseline supplement

This review covers only the Fedora QEMU baseline. The publisher image pins,
image signature verifier, native/KVM requirements and other distro gates stay
in place. The custom SQLite packages are CI fixtures, not official signed Fedora
updates and not a change to users' system package policy.

The source is Fedora's signed `sqlite-3.51.2-2.fc44.src.rpm`, SHA256
`f625466bdc4fefb2ba4dbb8b8a5b675d06a122a6bccb6cd0dfe5c4d1f68bf858`.
The reviewed Fedora 44 publisher key is
`36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. The builder imports that key from
the repository-pinned keyring and checks both source bytes and the RPM signature.
Build dependencies come only from signature-checked Fedora 44 release/updates
repositories. The complete installed dependency inventory is retained.

The retained WAL backport is combined with the exact upstream `walrestart.test`
from [SQLite commit fe57e14](https://github.com/sqlite/sqlite/commit/fe57e14b49f9189b56da8233ab3415ce5ff6b1ff),
plus its upstream callback cleanup described below.
The added test is discovered by the original complete test suite. The package
release is `2.omgci.walreset3.fc44` to distinguish it from the earlier privately
verified fixture. Its source, patch, key and pinned builder image are recorded
in `fedora-sqlite.json`.

## Build and supply

`fedora-sqlite.yml` runs a complete native `rpmbuild -ba`. The
[RPM manual](https://rpm.org/docs/4.20.x/man/rpmbuild.8) defines that command as a
full build including `%check`. The official spec retains its original `make
test`; the only check-section addition copies the per-assertion log before
RPM cleanup removes the build directory. There is no `--nocheck`, test filter,
relaxed timing predicate or extra retry. The original 1,800-second build bound
and ten-second kill grace remain.

The builder uses the original soft file-descriptor limit of 1,024. SQLite's
`oserror-1.1.3` checks error logging only if opening 20,000 connections exhausts
the available descriptors. The historical build used limit 1,024 and reported
393,833 assertions. The newer local Docker runtime permitted more than 20,000,
so that conditional assertion did not run and the passing full RPM build
reported 393,832. Same-binary controls passed all 13 `oserror.test` assertions
at limit 1,024 and all 12 applicable assertions at 65,536. No assertion was
deleted. The supply gate requires the error-path assertion to execute and pass,
as well as the new WAL assertions and the complete original test-file inventory.

Native CI builds the supply alongside its existing native application jobs.
Scheduled/manual QEMU runs build their own supply. Every artifact retains its
workflow-attempt name. Only the latest available attempt of the current workflow
run and exact checkout revision may be selected. The pinned
[download-artifact action](https://github.com/actions/download-artifact/blob/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/action.yml)
uses `digest-mismatch: error` by default. GitHub documents
[same-run artifact sharing](https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow)
and associates the [reusable workflow context with its caller](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#github-context).
No package registry, new key or external publisher is required.

## Native admission

The bundle binds the checkout revision, source/patch/key/builder identities,
architecture, complete successful check log, required executed assertions,
installed dependency inventory, source RPM and two native RPMs. Physical file
hashes, the exact file set and the library digest must match. Failed checks,
missing original test files, missing WAL/FD assertions, wrong provenance,
foreign architectures, path escapes and extra files refuse admission.

The guest queries native RPM identities and the RPM's library-file digest before
installation. Native RPM installs the two supplied packages with dependency and
digest checks intact. Admission then checks the actual resolved library bytes,
root ownership, exact package identity and `rpm -V`. The existing OMG lifecycle,
benchmarks, inventory rows, frozen-clone transactions and health checks continue
against that installed baseline. After the lifecycle, the library is checked
again and once more after all selected guest work. All three native receipts
and the supplied manifest are retained in the allowlisted QEMU evidence. The raw package bundle remains in its separate
immutable workflow artifact.

## Executed evidence and limits

The earlier `walreset1` fixture completed a full local RPM build with zero errors,
then passed the unchanged actual Fedora 44 guest lifecycle against OMG main
`f695d39dd2be9c6b287e40e6a7741c452439ed10`. The old installed library reproduced
corruption on round 3. The installed custom library completed 200 rounds with
all 81,795 committed rows recovered, matching exact IDs and passing integrity
before and after reopening. DNF5/libdnf5 remained `5.4.1.0-1.fc44`.

That evidence supports the WAL-code change, but it does not substitute for the
current supply build and candidate CI. Those must pass before this change
lands. ARM receives no runtime credit without its existing real native ARM/KVM
runner gate and guest evidence. This review does not establish the historical
cause of #626 or #623. The separate compatible dependency blocker #996 still
holds the product release.


## Fault callback cleanup

The original WAL regression from `fe57e14b` leaves a process-global fault
callback pointing at its destroyed Tcl interpreter. Hosted RPM checking reproduced
the next-file failure at `walro.test` with `[faultsim 500]`. The native two-file
control reproduced that failure and then passed 48 assertions with zero errors
when applying only SQLite's upstream cleanup. No assertion or expected value changes.

The patch includes `sqlite3_test_control_fault_install` before `finish_test`, as
in [SQLite's callback cleanup commit](https://github.com/sqlite/sqlite/commit/ea595494e202c9aa9d733bfe379e228f5cb828b6).
All original regression assertions stay intact. Full RPM and fresh candidate CI
must still pass; the two-file control alone does not qualify the package.


Missing supply is refused inside the individual guest's reporting scope, before
preflight or boot. An all-distro run therefore retains a failed Fedora receipt
and each other requested outcome. It cannot exit early without suite evidence.
The existing shell harnesses run in the early workflow target and again during
QEMU preparation, so reporting and interruption regressions surface before the
native build barrier.


## Download-action archive layout

The pinned download action flattens a single matching artifact, even when
`merge-multiple` is false. Its exact source includes `artifacts.length === 1`
in the destination-path condition. See the [pinned source](https://github.com/actions/download-artifact/blob/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/src/download-artifact.ts)
and [upstream report #455](https://github.com/actions/download-artifact/issues/455).

The producer puts the attempt directory inside the archive. Both consumers
merge these archives into one parent; each attempt retains its own directory.
Single and multiple downloads then have the same layout. The existing latest
attempt selector, exact source admission and pinned action's fatal digest
verification stay intact. No custom downloader or fallback to bad older supply.

## Reference-counted table formatting

The `eba415af` full RPM check failed in `fts5integrity.test:382` when Tcl 9
refused invalid Unicode in an EXPLAIN diagnostic. Native Fedora 44 SQLite 3.51.2
independently reproduces the underlying defect: the VCheck row's P4 contains
pointer bytes instead of the virtual table's name.

The pinned [pragma generator](https://github.com/sqlite/sqlite/blob/version-3.51.2/src/pragma.c)
uses `P4_TABLEREF` for VCheck. Its
[opcode implementation](https://github.com/sqlite/sqlite/blob/version-3.51.2/src/vdbe.c)
reads a `Table*`, and `vdbe.h` defines this tag as reference-counted `P4_TABLE`.
The [P4 formatter](https://github.com/sqlite/sqlite/blob/version-3.51.2/src/vdbeaux.c)
handles only `P4_TABLE`, so the reference-counted pointer falls through to the
string case. The supplement adds `P4_TABLEREF` to that existing table-name case.
It changes neither table ownership nor opcode execution.

The existing FTS5 file gains `fts5integrity-12.2.1`, asserting the actual VCheck
P4 table name after reopening the database read-only. Admission requires this
assertion exactly once. All existing assertions, original file inventories,
Tcl encoding behavior, RPM checks and limits remain. Older `walreset2` bundles
are refused under the new package identity and patch digest. Native full RPM
checking and fresh pinned-container CI remain required for this supplement.

### Native Fedora WSL evidence

On November 15, the complete source build at `c53b367f` passed the original
`rpmbuild -ba` checks on Fedora 44 WSL: 393,842 assertions and 46,391 fuzz cases,
zero errors. All 1,218 required test files retain the recorded inventory hash.
FD exhaustion, every WAL assertion and `fts5integrity-12.2.1` executed with their
required counts. The source signature, reviewed material hashes and resulting
package bundle passed the existing verifier.

The extracted built library has SHA-256
`e07afe6ae51f49e85faf6f577eae81bb207d86dc89658c9b83f335e833353050`.
A fresh Python process verified that exact mapped library, correct VCheck names
for ASCII, Unicode and quoted identifiers, and successful integrity checks.
The library was used only through a private process environment; the custom RPM
was not installed into the WSL system. This local WSL environment is not the
pinned CI container. Its bundle is not substituted for trusted workflow supply,
and it grants no ARM, KVM, guest lifecycle or product-release acceptance.

### Pinned hosted build

The [full RPM job at `8cec97cc`](https://github.com/omg-cli/omg/actions/runs/43754963552/job/132936970217)
passed in the policy's pinned Fedora image. Its PR merge commit is
`626d04ded85c04c4b7c8f8ccaafa902bdf3793b1`; its Git tree equals the PR head's
`be4f4b1c0c3db85e3aef79637a5c4d69cd0bfcfc`.

The [bundle artifact](https://github.com/omg-cli/omg/actions/runs/43754963552/artifacts/14178660473)
has SHA-256 `56388f00550d18b800ee2a2e41a387c80d7e1fb8a64f5eb1009e5b66fcb65115`.
After digest verification, the existing bundle verifier admitted it against
that exact merge revision and current policy. Its 393,842 assertions, 46,391
fuzz cases, 1,218-file inventory and required assertion counts all pass. The
built library hash equals the independently built WSL library hash above.
This closes the pinned source-build check; product guest execution, ARM and
release acceptance remain separate requirements.

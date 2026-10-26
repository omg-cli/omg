# Fedora 44 SQLite WAL baseline supplement

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
from [SQLite commit fe57e14](https://github.com/sqlite/sqlite/commit/fe57e14b49f9189b56da8233ab3415ce5ff6b1ff).
The added test is discovered by the original complete test suite. The package
release is `2.omgci.walreset2.fc44` to distinguish it from the earlier privately
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
again. Both native receipts and the supplied manifest are retained in the
allowlisted QEMU evidence. The raw package bundle remains in its separate
immutable workflow artifact.

## Executed evidence and limits

The earlier `walreset1` fixture completed a full local RPM build with zero errors,
then passed the unchanged actual Fedora 44 guest lifecycle against OMG main
`f695d39dd2be9c6b287e40e6a7741c452439ed10`. The old installed library reproduced
corruption on round 3. The installed custom library completed 200 rounds with
all 81,795 committed rows recovered, matching exact IDs and passing integrity
before and after reopening. DNF5/libdnf5 remained `5.4.1.0-1.fc44`.

That evidence supports the WAL-code change, but it does not substitute for the
new `walreset2` supply build and candidate CI. Those must pass before this change
lands. ARM receives no runtime credit without its existing real native ARM/KVM
runner gate and guest evidence. This review does not establish the historical
cause of #626 or #623. The separate compatible dependency blocker #996 still
holds the product release.

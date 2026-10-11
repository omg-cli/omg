# Fedora RPM database fixture

`fedora-publicsuffix.rpmhdr` is the unmodified `Packages.blob` for
`publicsuffix-list-dafsa` from the image
`fedora:latest@sha256:6c75d5bf57cb0fa5aa4b92c6a83c86c791644496d9ac230de7711f5b8ec3b898`.
The database is `/usr/lib/sysimage/rpm/rpmdb.sqlite`.

Select the record with:

```sql
SELECT blob FROM Packages JOIN Name USING(hnum)
WHERE Name.key = 'publicsuffix-list-dafsa';
```

The 5676-byte fixture has SHA-256
`b8199f16ec4695266286e869b4125059073bf7c7f01ebced2bf2461b4b669deb`.
It is a database header, not a complete RPM archive or executable payload.

Native `rpm -q publicsuffix-list-dafsa --qf '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{SUMMARY}\n'`
inside that image returned:

```text
publicsuffix-list-dafsa
20260116
1.fc44
Cross-vendor public domain suffix database in DAFSA form
```

Unlike the earlier synthetic fixtures, this record starts with the two big-endian
entry/data lengths and has no archive magic prefix. The integration test inserts
these exact bytes into SQLite and reads them through the production database reader.

## Translated native header

`fedora-gnat-srpm.rpmhdr` is the unmodified `Packages.blob` for
`gnat-srpm-macros` version `7` in the Fedora 44 Cloud 44-1.7 guest after
installing RPM build tools. Its SHA-256 is
`5c70d6f87c2adf1c31c584b306d918429024d43206fe848c9246a71028af7c5a`.
Both SUMMARY (1004) and DESCRIPTION (1005) have I18NSTRING type 9 and count 2.
The old reader rejected this real record because it imposed the scalar STRING
count-one rule on translated arrays.

The regression exercises the production SQLite reader. Array validation checks
all declared terminators inside the payload. Package summaries use the first,
default-locale string, matching `LC_ALL=C rpm` for this fixture.
See <https://rpm.org/docs/6.0.x/manual/tags.html>.

## Native DNF upgrade records

`fedora-installed.tsv` and `fedora-upgrades.tsv` were captured from the same pinned
Fedora image using `dnf repoquery --installed --latest-limit=1` and
`dnf repoquery --upgrades --latest-limit=1`. The query format contains actual tab
and newline characters between `name`, `arch`, `evr`, and `repoid` fields.

The capture contains 146 installed records and 58 upgrade candidates. Repository
contents can change; these are parser/matching fixtures, not an assertion that a
future Fedora installation must have exactly 58 updates. Matching uses both name
and architecture and preserves native EVR text rather than comparing with semver.

SHA-256 values:

- Installed: `fe05430102cda666217ecf3a1fbd01d91a133086995078a4cf3d5df22467e823`.
- Upgrades: `10ca59439c192f538a7aa50ea340a335e17f68ebcc1fb1ccdcf76842a410a2f3`.

## Native epoch identity header

`fedora-xz-libs.rpmhdr` is the unmodified `Packages.blob` for `xz-libs`
from the FedoraLinux-44 WSL audit environment on 2026-10-09. Native RPM returned
`xz-libs 1:5.8.2-2.fc44.x86_64`; EPOCH (1003) has INT32 type 4 and count 1.
The fixture SHA-256 is
`d6a49c91d15926152661bd2912cd07865bb4cc0e86a013b97514c59bea1ea09b`.
It is an inert database header, with no executable payload.

The inventory regression changes only EPOCH type/count while preserving its
four payload bytes. Native librpm rejects BIN/count4, INT16/count2 and
INT8/count4 variants; the reader must reject these instead of interpreting
their bytes as a valid package epoch. The unmodified fixture verifies the
package name, architecture and exact EVR returned through SQLite.

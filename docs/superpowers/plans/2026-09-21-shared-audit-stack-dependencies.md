# Shared audit integration dependencies

The shared CLI/daemon audit in PR #445 must not rely on fixes present only in PR #447. Review of the split found Arch still queried as an OSV ecosystem and advisory applicability types introduced after the split.

## Evidence and integration decision

- OSV's ecosystem registry does not include Arch: https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py
- Native Arch advisories must retain fixed groups: an installed older version is not safe merely because a fix is published. The affected snapshot is not an introduction boundary.
- Native Fedora applicability and severity must come from DNF, with complete enabled-repository evidence and installed RPM identities. Published advisory severity is not invented CVSS.
- Bring the existing native advisory and installed-identity implementations forward together. Keep SBOM exports in their later slice because #445 does not contain `sbom_shared.rs`.

## Source commits ported

Retain fixed groups and comparison semantics: e35c13e3, 7f785bc6.
Native advisory schema and Fedora orchestration: 1fc57ca4.
Installed inventory: 3417b6e9.
RPM applicability validation prerequisite: 67e720c2.
Affected identity propagation: 6a8833a2.
Arch native audit: 26141a17 excluding the later SBOM file.
Arch candidate grading: 8d2d72c3.
Supported OSV test ecosystems: d1438341.

## Verification gates

Run formatting, security unit tests, package-manager tests, real Unix audit transport tests, and QEMU output-oracle tests on the combined slice. Verify Arch and Fedora feature owners, then Debian/Ubuntu owners. Obtain fresh hosted checks before merging; prior later-branch evidence does not prove this port. Keep #445 unpushed until its dependency assembly is validated to avoid redundant partial builds.

The global reviewed behavioral denominator, current-revision hosted matrix, and independent final review remain outstanding. None of these source ports establishes the 95% goal by itself.

## Local validation of assembled source tree 4c42c446

- Formatting passed.
- Arch: 129 security tests, 294 package-manager tests, 2 real Unix audit transport tests and 20 QEMU oracle tests passed. Two package-manager tests were ignored and receive no coverage credit.
- Fedora: 148 security tests, 72 package-manager tests, 2 real Unix audit transport tests and 20 QEMU oracle tests passed.
- Ubuntu: 152 security tests passed; package-manager validation stalled in kernel memory-map locks. Evidence and unresolved recovery tracked in #467. Transport and oracle tests were not reached in that run.
- Debian validation of this assembly remains pending.
- An initial transport filter selected zero tests; it was corrected and both actual transport tests ran on Arch and Fedora. An edited Windows-mounted helper interrupted Fedora's first orchestration run; copying the stable helper into Linux completed the corrected run. Neither preliminary run was credited as a full pass.

This is a local integration checkpoint, not approval to merge. Fresh hosted evidence and the unresolved local failure remain explicit gates.

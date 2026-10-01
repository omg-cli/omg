# Wave-12 BLOCKER Remediation Plan (citation: /tmp/omg-fleet12/aud-*.md)

> Historical fleet audit plan. Its temporary report paths, implementation decisions, and status marks describe that review; they are not current completion evidence. See the [current documentation index](docs/index.md) for supported behavior and the [open issue backlog](https://github.com/omg-cli/omg/issues) for active work. The original plan remains below for provenance.

Status legend: [x] fixed+pushed, [ ] open. Each item cites its auditor evidence.

- [x] B01 AUR success printed before outcome check — fixed 5a843ac
- [x] B02 elevated pre-separator flag drop — fixed 5a843ac

## Decision (per 8/27 converging blockers): delegate Debian mutations to apt/dpkg

behind the existing privilege boundary rather than repairing the pure engine,
unless a full write-ahead undo journal + complete dpkg state machine is built.
Affected: transaction.rs (14 blockers: locks, journal, .list/info state,
upgrade protocol, conffiles, /tmp tmpfs exhaustion).

## Signature chain (5 blockers): parallel_sync/sources must verify clear-signed

InRelease against Signed-By keyring (reuse sequoia), bind Packages hashes to the
authenticated Release, enforce Valid-Until, reject HTTP/trusted=yes; add
hostile-mirror fixtures BEFORE any other sync work.

## Sync/index disconnect (3 blockers): db.rs reads /var/lib/apt/lists while sync

writes OMG cache — pick one authoritative source after signatures exist.

## AUR sandbox (3 blockers): never mount ~/.gnupg into --share-net sandbox

per-build PKGDEST/SRCDEST with artifact digests verified pre-install; fresh
VCS-free checkout per build (git hooks escape via planted .git/hooks).

- [x] FIXED: ~/.gnupg ro-bind removed from the bwrap sandbox entirely
      (aud-aur-client: private-key exposure to untrusted PKGBUILDs).
- [x] PARTIAL: both `git pull --ff-only` sites now run with
      core.hooksPath=/dev/null, GIT_CONFIG_NOSYSTEM=1 (planted-hook escape);
      full fix remains fresh VCS-free checkout per build.

## Review ordering (1 blocker): move review_pkgbuild before parse/download_sources

typed source-rename validation; byte caps.

- [x] FIXED: review_pkgbuild now precedes parse_sources/download_sources in
      aur/client.rs install(); duplicate later gate removed (aud-aur-client).
- [x] FIXED: launcher socket unlink removed — omgd owns stale-socket removal
      under the singleton lock (wave-11 MASTER, cli/commands.rs).

## Also open from wave-11 MASTER (/tmp/omg-fleet11/MASTER.md): socket unlink in

launcher, PackageService bypass on install paths, aur_index mmap invariant,
audit-log HMAC/anchoring, STUB JWT key (needs production key).

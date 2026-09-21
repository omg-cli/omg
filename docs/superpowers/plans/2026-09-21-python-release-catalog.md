# Python release catalog implementation plan

> Execute inline with superpowers:executing-plans. No subagents, per user instruction.

**Goal:** Resolve supported Python downloads without depending on shared unauthenticated GitHub REST quota, preserving exact platform/version selection and mandatory SHA-256 verification.

**Spec:** The approved OMG/OMGD verification goal and issue #459.

**Architecture:** Fetch Astral's public UV Python download metadata over HTTPS with the existing bounded-response client. Select standard CPython entries for OMG's supported Linux GNU and macOS x86_64/aarch64 targets, validate metadata against the release URL and checksum, and feed the existing verified download/staged installation path. Retain bounded GitHub discovery only for exact historical versions absent from the catalog; malformed metadata and transport failures are errors, not permission to bypass verification.

**Tech stack:** Existing Rust, reqwest, serde and runtime download/extraction helpers; no new dependency or guest credential.

## Evidence and constraints

- Failure: #443 revision 3a5a0e93, QEMU run 35564230589, Ubuntu Python 3.12.14 installation refused HTTP 403 with remaining quota zero. Preserve this run and issue #459.
- GitHub documents unauthenticated limits as IP-scoped: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api.
- Astral's catalog: https://raw.githubusercontent.com/astral-sh/uv/main/crates/uv-python/download-metadata.json.
- Upstream documents install_only_stripped as equivalent to install_only without debug symbols: https://gregoryszorc.com/docs/python-build-standalone/main/running.html.
- Keep exact version/architecture/libc/threading selection; reject absent or malformed hashes and inconsistent URLs. Do not convert provider errors to empty successful catalogs.
- Reuse the production archive digest, staging, internal-binary and activation checks. Keep the QEMU install and executable-version assertions unchanged.
- Local tests are not fresh hosted evidence. Do not close #459 merely because a retry passes.

## Steps

- [ ] Add a focused catalog parser near the Python runtime manager, with deterministic fixtures for supported targets, version/prerelease ordering, excluded variants, malformed checksums, mismatched URLs and unsupported schema.
- [ ] Fetch metadata with existing response/time bounds. Test HTTP errors and malformed bodies using loopback fixtures; no ambient token or endpoint override.
- [ ] Integrate catalog selection into Python listing/installation, reuse a fetched catalog for partial-version resolution, preserve historical exact-version fallback and existing fail-closed digest checks.
- [ ] Run narrow unit checks and negative controls; run real installs in isolated WSL state on all four distros and execute Python/pip/stdlib probes. Inspect cleanup and unchanged unrelated state.
- [ ] Move the bounded fix to the blocked #443 branch, preserving later branch changes. Include the pending native no-retry/admission corrections in the same validation batch.
- [ ] Require fresh hosted native and QEMU results, inspect failure issues/evidence, then merge in dependency order under standing authorization.

## Review focus

Unknown catalog schema, missing hashes, wrong target/variant, stale historical availability, and redirect/source trust require explicit tests or documented limits. This change does not establish full Python lifecycle coverage or the global 95% target.

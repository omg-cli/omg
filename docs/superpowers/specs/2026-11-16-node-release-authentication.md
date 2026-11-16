# Authenticate Node release manifests before candidate execution

The user delegated implementation choices to improve OMG's package and runtime security, including reducing exposure to CVEs and zero-days. This change authenticates a runtime publisher; it does not establish that signed code has no vulnerabilities. Runtime advisory matching, fresh feeds and installation isolation remain separate requirements in the advisory coverage design.

## Observed gap and selected approach

`NodeManager::install` resolves a release, fetches `SHASUMS256.txt`, checks the archive SHA256, extracts it and executes a candidate probe before publication. The checksum manifest currently has HTTPS transport integrity but no releaser-signature verification. Node's official verification instructions require a signed checksum manifest and its release keys.

Use `SHASUMS256.txt.asc` as the primary input and authenticate its cleartext with the existing Sequoia PGP backend before selecting an archive checksum. Some legitimate releases lack the detached `.sig` sidecar, so requiring that sidecar alone would incorrectly reject an available signed manifest. Never fall back to the unsigned manifest after authentication fails.

Bundle a reviewed immutable snapshot of Node's public release certificates and explicit primary fingerprints. Do not trust arbitrary certificates served next to the archive or refresh signing authority automatically. The researched upstream snapshot is `nodejs/release-keys@481637f813e912c4aa3622d7964ab426c97b8e8d`; its 29 key files are candidates, not yet validated or admitted trust roots. Verify each Git blob and actual primary fingerprint, and cross-check active signers against Node's published release-key list before vendoring. Retain provenance and SHA256 receipts. Unknown newly introduced signers fail with an actionable authentication error until a reviewed key update.

## Invariants

- Authenticate before extracting a checksum, downloading an archive or executing any candidate code.
- Reuse the existing PGP signature policy, current-time validity and alive/nonrevoked signing-key checks. Preserve existing detached verification semantics and tests.
- Use Sequoia's cleartext streaming verifier, not custom dash-unescaping, canonicalization or signature-packet extraction. Consume verified EOF before returning plaintext.
- Bound signed input and plaintext to 1 MiB each. Reject unsigned/non-cleartext containers, malformed/truncated input, missing signatures, unknown keys, weak hashes, future/expired signatures, expired/revoked keys and excessive output.
- Match the exact resolved version's artifact filename in the authenticated manifest; preserve existing SHA256 validation and HTTPS retry/deadline behavior.
- Default builds already include `pgp`. A build without it must report unsupported authenticated Node installation rather than bypass verification.
- Never modify the user's GPG keyring or fetch/import new trust roots during installation. An embedded bundle may be loaded through a private temporary file and the existing fingerprint-allowlisted loader; no new dependency is necessary.
- Existing installed-version activation is not provenance re-verification. Do not claim this change authenticates historical installations or screens known vulnerable versions.
- No Node binary execution or download during signature fixtures. Network tests use the existing real HTTPS fixture with fixed local routes and trusted fixture certificates.
- Work solo in the existing main checkout. Keep the original coverage comparator, 64M capacity, native storage limits and existing stronger acceptance gates. No merge/release before required validation and review.

## Compatibility and release review

Old releases signed by currently expired/revoked keys may be refused. Report that limitation; do not disable cryptographic policy to accept them. Missing or rotated signer keys must produce a clear error, never a success message. Confirm behavior in `pgp` and no-`pgp` builds. The new trust asset must be included in source packaging and tracked with its refresh instructions.

Verification must include generated good/tampered/foreign/expired/revoked cases, cleartext canonicalization and resource bounds, and a real vendor-signed fixture with pinned provenance. Existing checksum retry/integrity tests must retain their assertions while moving to signed fixtures. A controlled bypass fault must fail the end-to-end rejection test. Native proof, public CI, packaging, and independent security review remain required; a green unit test is not proof of complete supply-chain security.

## Primary references

- https://github.com/nodejs/node#verifying-binaries
- https://github.com/nodejs/node/blob/main/doc/contributing/releases.md
- https://github.com/nodejs/release-keys
- https://github.com/nodejs/node/issues/58249 (release lacking detached sidecar)
- Sequoia 2.4.1 source pinned by Cargo.lock; verify the actual cached streaming API before implementation.

# Node release certificates

`node-release-keys.asc` concatenates the eight active releasers' exact public
certificate files from [nodejs/release-keys at commit
481637f813e912c4aa3622d7964ab426c97b8e8d](https://github.com/nodejs/release-keys/tree/481637f813e912c4aa3622d7964ab426c97b8e8d/keys).
The upstream MIT license is preserved in `LICENSE-node-release-keys.md`.
Only its trailing blank line is removed; provenance records both license hashes.

The active primary fingerprints match Node's [release-key list](https://github.com/nodejs/node#release-keys)
observed on 2026-11-16, README Git blob
`3b7d93827ae99ff451a4ff9016dbd254cd5776b8`. Retired authorities are excluded.
Historical releases signed only by excluded authorities may consequently fail
authentication. There is no unsigned fallback or automatic authority refresh.

The bundle SHA-256 is
`00308f9791e6ccfafe96179770dc1b4c6acdb3a23b771965bdd01084ccc92a32`.
Per-certificate Git blob IDs, SHA-256 digests and expected primary fingerprints
are recorded in
`tests/fixtures/node-release-authentication/provenance.json`.
The bytes retain the pinned upstream representation. A GPG-exported keyring can
have different bytes and must not substitute for this digest.

To update the trust set, pin a new upstream commit, independently compare its
active primary fingerprints against Node's current list, verify each Git blob
and parsed public certificate, review authority additions/removals and expiration
or revocation changes, and refresh the signed interoperability fixture. Run the
native authentication, tamper/unknown-signer and packaging checks before release.
Never import these certificates into the user's personal keyring.

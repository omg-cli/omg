# Node signature interoperability fixture

`SHASUMS256-v24.22.3.txt.asc` is the official cleartext-signed checksum manifest
retrieved from Node's `latest-v24.x` distribution on 2026-11-16. Its SHA-256 is
`aaaff9ec5c8c5f0997786c06088134ddb4b21a41f74e872b30ed1acca309e2b5`.
The signed plaintext names `node-v24.22.3-linux-x64.tar.xz` with archive SHA-256
`4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb`.

This fixture contains public signature/checksum data. No runtime archive was
downloaded or executed to produce it. `provenance.json` binds the original source,
the pinned certificate inputs and expected archive identity. Authentication tests
must retain current-time key/signature checks; a future authority change may
require a reviewed fixture refresh rather than disabling those checks.

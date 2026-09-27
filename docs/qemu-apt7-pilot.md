# APT 7 QEMU pilot

`QEMU APT 7 pilot` is a manual, staged x86_64 workflow. Select `all` to build
one `debian-trixie` archive from the selected revision and test that exact
artifact in separate Debian 13 and Ubuntu 26.04 KVM guests. Each guest checks
its `/etc/os-release` ID and version, the archive checksum, `libapt-pkg.so.7`,
the native `tree` install/remove/local-file lifecycle, and the admitted
`hermetic,container` CLI inventory selection. The jobs upload distinct
`qemu-evidence-debian13` and `qemu-evidence-ubuntu2604` artifacts even on
failure. The final result job fails when a selected guest or build fails.

The pilot does not change the four required QEMU Matrix lanes. It does not run
the published-release, ARM, network, PTY, nested-container, or native
transaction-benchmark tiers. The trusted `QEMU Failure Reporting` workflow
currently tracks QEMU Matrix and CI on `main`; inspect pilot artifacts and
job conclusions directly. Keep the pilot manual until both hosted guest
artifacts pass and their inventory admission receipts are reviewed.

Image pins are in `tests/qemu-image-provenance/apt7-manifest.json`. Debian's
dated Trixie image is checked against its SHA512 digest. Ubuntu's dated 26.04
release image is checked against SHA256SUMS signed by the pinned Ubuntu cloud
image key. Renew those pins and their review expiry together.

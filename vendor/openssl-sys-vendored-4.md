# Temporary OpenSSL vendoring patch

OMG pins the official rust-openssl repository at
`9e94ed8675853c09e98a86ca3bb99a989f12b674`, the immutable head of
[upstream PR 2692](https://github.com/rust-openssl/rust-openssl/pull/2692).
This is an unmerged upstream change without maintainer approval.

Released `openssl-sys 0.9.118` selects the 300.x `openssl-src` series,
which bundles OpenSSL 3.6.3 and misses subsequent security fixes.
[Upstream issue 2714](https://github.com/rust-openssl/rust-openssl/issues/2714)
tracks the released vendoring limitation.

The patch adds an opt-in `vendored-4` feature and selects the compatible
400.x source builder. It changes no cryptographic implementation, bindings,
validation, or `OPENSSL_NO_VENDOR` behavior. The selected source builder is
`openssl-src 400.0.2+4.0.3`. OpenSSL 4 support already exists in the pinned
base. Bundling it preserves portable package-signature verification and
post-quantum APIs without adding a shared OpenSSL runtime requirement.

Both `vendored` and `vendored-4` are enabled because the upstream patch still
uses the former to disable watching generated headers. Enabling only the
latter makes every Cargo invocation rebuild OpenSSL. The patch explicitly
selects the 400.x builder when both features are enabled. The obsolete
300.x builder and its OpenSSL 3.6.3 sources remain downloaded and locked,
but its bundled C is not compiled or linked. This workaround does not mean
that every downloaded source is patched. Verify the selected OpenSSL 4
build and static linkage, and confirm that an unchanged repeat build is fresh.

The direct `openssl-sys` dependency only activates this feature for `pgp`.
The Git source allowance in `deny.toml` is restricted to the official
repository. No advisory exception is added.

Remove the patch, direct feature dependency, and Git source allowance when
a released `openssl-sys` provides patched vendoring. Verify actual detached
PGP and SLSA signatures, JWT validation, static linkage, Linux platform
checks, and vendored macOS CI before admitting this workaround.

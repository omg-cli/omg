# Temporary rust-apt version-boundary correction

This is the published rust-apt 0.11.3 crate, archive SHA-256
`6f3baa272fd784ce1a791ea2ef2f599fca23fbbbced7782a05c6f5007431ec79`.
Upstream source revision: `045d2a6cddca05e23f969c462ff429d248dd3932`.
The upstream license and files are retained.

The only upstream code change is in `apt-pkg-c/util.h`: copy both Rust version
slices into terminated C++ strings before passing them to APT's comparator.
On libapt-pkg 3.0.3, numeric fragment loops can read beyond the supplied end
pointer. Passing the prefix `1:1.0-1` of `1:1.0-1999999` compared greater than
an identical separate string. A standalone C++ reproduction showed the same
failure; terminated copies returned equality.

Tracked in https://github.com/omg-cli/omg/issues/481. The executable regression
is `tests/apt_version_ordering.rs`, selected by native APT CI owners. Do not
remove the test or accept the upgrade based on compilation alone. Remove this
override after an upstream release fixes the boundary and passes the same
regression on the supported APT6/APT7 baselines. This correction does not solve
artifact ABI selection and is not evidence of a speed improvement.

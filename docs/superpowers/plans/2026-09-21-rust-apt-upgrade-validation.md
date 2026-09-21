# rust-apt upgrade validation

Upgrade the binding from 0.10.0 to 0.11.3 without changing APT artifact routing.
The candidate failed a new dpkg-oracle regression for bounded version slices.
A standalone C++ reproduction against Debian libapt-pkg7.0 3.0.3 returned
unequal for identical version text with trailing backing bytes; copying the
bounded inputs into terminated strings restored equality. Track this in #481.

The exact upstream crate is temporarily vendored. Only apt-pkg-c/util.h changes
upstream code, to terminate both strings at the native boundary. Preserve its
license, archive identity and removal criteria in vendor/rust-apt-0.11.3/OMG-PATCH.md.
Archive comparison confirmed only that header differs, plus the patch note.
The additional source volume is retained upstream code, not new OMG behavior.

Validation before extracting this patch onto main: the unmodified 0.11.3
regression failed. With the correction it and all six native APT unit tests
passed as omg-audit on Debian13 and Ubuntu26 using the same candidate binaries.
Targeted strict Clippy passed. These are APT7 checks on the earlier trial tree,
not current-branch hosted evidence or APT6 transaction coverage.

The standalone branch is based on main 2401eb61521055119b2e9238b83567a8bcaa13ad.
Twenty native-selection tests, seven Docker workflow tests and formatting pass
on this branch. Native APT owners explicitly select the new regression.
Cargo-chef 0.1.78's recipe omitted the optional path patch; reconstructing it
failed dependency resolution until vendor was copied before cook. Locked,
offline resolution then passed. A complete image build is still required.

Before merge: inspect hosted legacy APT6 and APT7 test outcomes, Docker build,
all applicable native/QEMU gates, and the version regression's actual execution.
Verify real transaction and repository-information refusal behavior in disposable
environments. Do not claim performance gains, resolve #476, dismiss #479, or
claim the broader 95% behavioral target from this patch.

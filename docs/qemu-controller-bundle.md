# Same-run x86 QEMU controller

The x86 matrix builds one QEMU 10.0.14 controller and distributes a Docker-save
archive to its five guest lanes. Every lane requires that artifact. A failed
build, missing download, digest mismatch, or image mismatch stops the lane;
there is no package-controller fallback in this CI route.

The build job independently publishes the archive SHA-256, raw receipt SHA-256, and Docker image ID.
Consumers compare those outputs with the receipt and archive, load the archive,
and inspect the actual image ID and source revision. The receipt also records
the repository, source SHA (including a PR merge revision), run and attempt,
authenticated source archive, release-manager key, executable hashes, and
firmware hashes. A receipt inside the archive cannot authorize itself.

Source authentication checks the pinned archive bytes and reviewed public key
before extraction, then requires the upstream signature's exact fingerprint.
The compile runs in a separate container with two CPUs, 8 GiB, and a
1,800-second timeout. The guest controller retains its existing 3 GiB allocation
and 600-second package bootstrap.

The controller's source-built executables are absolute paths under
`/opt/omg-qemu-10.0.14/bin`. Image inspection, creation, conversion, resize, and
checking use that qemu-img, including transaction clones. The source-built
system executable uses the packaged stable QEMU and SeaBIOS firmware at its
configured data path. Firmware collisions require equal bytes. After package
bootstrap, the lane checks the actual source executable hashes and versions,
firmware bytes, and the libslirp library resolved by that executable.

Manual invocations without a bundle and ARM lanes keep their existing Debian
package controller. Those routes have not been upgraded by this change.
Building an aarch64 target on x86 would not prove native ARM execution.

The completed local prototype established first SSH readiness with default VGA,
SATA disabled, and VAPIC disabled. It did not establish the full shipping guest
contract. This candidate still requires actual build/load admission and all
five exact-head x86 guest receipts, including lifecycle, network, and
transaction checks. Upgrading QEMU with default VGA does not satisfy issue
#896's separate requirement to remove the VGA device.

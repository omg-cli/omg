# Optional controller image measurement

`qemu-controller-measurement.yml` compares a prebuilt controller with the existing
apt setup on native x64 and ARM64 Linux runners. It runs only for changes to this
extension, or an explicit workflow dispatch after the workflow is available on
the default branch. The production guest controller and libslirp transport keep
their existing setup.

Each producer builds from a small context containing the Dockerfile and the
existing package verifiers. The base image is digest-pinned. QEMU package floors,
the exact libslirp package download digest and its loaded runtime version are
checked during the build. There is no registry publication or registry login.

A fresh consumer downloads that producer's same-run artifact. Before invoking
`docker load`, the checkout's validator checks the archive and config hashes
against producer job outputs, checks source/platform/base labels, and hashes each
expanded layer against its config diffID. Archive paths, member kinds, JSON,
layer expansion and total bytes are bounded. Artifact-provided code is never
used to validate the archive. A checksum file within an artifact alone is not a
trusted expected digest.

The consumer checks that the candidate image was absent, records the existing
image inventory, loads the verified archive, and checks the loaded identity.
Disposable containers use two CPUs, 3 GiB memory, 512 PIDs and the existing
NET_RAW/NET_ADMIN capability drops. The package floor and actual loaded libslirp
version are checked again. A separate disposable base container runs apt and the
existing installers for a comparison sample. Only uniquely named measurement
containers are cleaned up; no global image or build-cache pruning occurs.

Inspect `steps.json` for command durations, statuses and log hashes;
`measurement.json` records the verified image identity and comparison limits.
GitHub's download step duration supplies the separate artifact-delivery time.
Preserved failure logs are evidence of a failed measurement, not a speedup.

This is one sample per architecture. Shared base layers, mirrors and host caches
are not cold, and artifact delivery is not registry pull. These results do not
establish guest lifecycle correctness, a transport change, durable image
publication or production adoption. Those require their own review and actual
guest execution before changing the default controller.

Local checks (no Docker access needed):

```sh
python3 -B scripts/test_qemu_controller_image.py
python3 -B scripts/test_controller_measurement.py
```

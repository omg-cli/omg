# OMG versus native package managers

The performance question is how long OMG and the native package tool take to
complete the same useful operation on the same distribution. Smoke tests gate
that comparison; their duration is not the comparison itself. Publish measured
speedups where OMG wins, and retain parity, regressions, and unsupported cases.

## Comparison contract

Use the following native baselines. These are candidate comparisons whose output
and state must pass the equivalence checks before timing, not new measured results.

- **Arch.** Compare repository search with `pacman -Ss`, repository information
  with `pacman -Si`, and explicit installed packages with `pacman -Qqe`.
  Use repository-only OMG search and the same repository snapshot. `yay` is an
  optional additional comparator, not the default package-manager baseline.
  The current guest info profile queries installed `tree` with `pacman -Qi`;
  repository `-Si` is a distinct profile, not an interchangeable label.
- **Debian and Ubuntu.** Report `apt search` and `apt show` as user-facing baselines.
  Also report `apt-cache search` and `apt-cache --no-all-versions show` as cached
  metadata baselines when comparing offline indexed queries. Do not pick only
  the slower APT invocation. Query installed state with `dpkg-query`, not a
  repository search. Explicit/manual packages mean installed manual packages,
  not every package in the database. `apt-mark showmanual` already filters out
  packages without an installed version: see `ShowAuto` in
  [APT 2.6.1](https://github.com/Debian/apt/blob/2.6.1/cmdline/apt-mark.cc#L277-L313)
  and the [Ubuntu APT 2.8.3 source](https://archive.ubuntu.com/ubuntu/pool/main/a/apt/apt_2.8.3.tar.xz).
  Verify the installed subset during preflight; do not add a redundant timed
  `dpkg-query` intersection that artificially slows the native comparator.
- **Fedora.** Use DNF for repository search, information, installation, and removal.
  Record whether the image provides DNF4 or DNF5 and use that version's documented
  syntax. RPM queries such as `rpm -q` and `rpm -qa` measure installed-package
  state, not available repository search. A fast empty installed-package search
  cannot beat a successful DNF repository search.

For search, normalize package identities, architecture, repository scope, and
result limits before declaring equivalence. OMG currently defaults to a 15-result
limit; native commands can return all matches. JSON search preserves installable
package names but still honors the requested limit. A shared query string does not
make fuzzy, regex, name-only, and description searches equivalent. If equivalent
semantics cannot be established, label the result as non-comparable and do not
publish a speedup. Do not truncate the native command's output through `head` to
make it appear equivalent after it has already performed different work.

For information queries, compare the same candidate package version and the
fields the task requires. For installed-package queries, compare normalized sets
before comparing counts. Any wrapper needed for counting is part of the timed
end-to-end command and must be disclosed for both sides.

For install/remove benchmarks, use a fresh overlay for every measured sample,
verify the initial state, and verify native state afterward. Separate cached
package archives from network-inclusive downloads. A second install of an already
installed package is an idempotency benchmark, not installation latency. Never
present ordinary `apt-get update`, repository synchronization, and OMG's update
*discovery* as the same operation without establishing their semantics.

Report `native mean / OMG mean` per matched operation and distribution, alongside
both absolute times, medians, variation, sample counts, cache state, and raw data.
A ratio greater than one favors OMG. Failed or non-comparable cases have no ratio.
Measure daemon startup/index-building separately and report the command count
needed to amortize that cost; warm-query wins do not make initial setup free.

The [APT command reference](https://manpages.debian.org/bookworm/apt/apt.8.en.html)
and [apt-cache reference](https://manpages.debian.org/bookworm/apt/apt-cache.8.en.html)
distinguish interactive operations from cached metadata queries. DNF5 documents
[search](https://dnf5.readthedocs.io/en/latest/commands/search.8.html) and
[repoquery](https://dnf5.readthedocs.io/en/latest/commands/repoquery.8.html) separately.
Validate these choices against the native versions actually installed in each guest.

## What the evidence proves

OMG supports four x86_64 Linux release targets for this verification program:
Arch, Debian, Ubuntu, and Fedora. This is not a claim about every Linux distribution.
Container tests share the host kernel. They do not prove guest kernel, systemd,
reboot, login-shell, or real terminal behavior.

The [local v0.1.218 record](records/release-smoke-v0.1.218-local.json) preserves
12 case results, artifact hashes, image references, and the exact runner commit.
It is one observation per case, not a statistical benchmark. The original result
file's SHA-256 is included for traceability. Host performance metadata was not
captured, so these timings must not become cross-machine performance claims.

The case order below is search, install, then remove:

- Arch passed in 4, 2, and 4 seconds.
- Debian passed in 11, 12, and 13 seconds.
- Ubuntu passed in 24, 26, and 24 seconds.
- Fedora reported `PRODUCT_FAIL`, `PRODUCT_FAIL`, and `HARNESS_ERROR` in
  12, 9, and 9 seconds. Removal's prerequisite install failed; removal was not tested.

The clock covers container execution, index preparation, assertions, and cleanup.
It excludes artifact acquisition and image pulling. The runner uses Bash's
whole-second clock, which is unsuitable for millisecond CLI benchmarks.
All twelve local cleanup logs recorded verified container absence. A separate
engine query found no remaining smoke containers. These checks establish process
cleanup, not secure erasure of data from storage.

[CI run 33912270669](https://github.com/PyRo1121/omg/actions/runs/33912270669)
ran the same runner commit independently. Arch, Debian, Ubuntu, and runner fixtures
passed. Fedora remained red. Its uploaded artifacts contain per-case transcripts,
metadata, result JSON, and cleanup logs. GitHub artifact retention is finite;
retain the archive and its digest before using it as long-term release evidence.

The release-smoke record above contains Docker results. The separate
[four-distro QEMU runner](../scripts/README.md#benchmark-qemush) now has a
[committed live receipt](records/qemu-four-distros-20260905.json) for Arch,
Debian 12, Ubuntu 24.04, and Fedora 44. All four guests passed reboot, sudo,
package lifecycle, native-version checks, and cleanup. The receipt retains
240 raw warm timing samples and artifact hashes. Its `default_path_follow_up`
records a later no-benchmark run against the failure-handling fixes. Arch,
Debian, and Ubuntu passed in that suite. Fedora passed on a separate retry after
a Docker controller-creation timeout. Both the failed suite and retry remain
in the receipt rather than presenting them as one uninterrupted green run.

Arch and Ubuntu used unchanged published archives. Debian and Fedora used
locally built candidates. These debug candidates and single-guest samples do
not establish release speedups. The published Debian artifact fails on a fresh
Bookworm installation without its archive-directory initialization fix. It also
fails to load on Debian 13 because of its libapt-pkg.so.6.0 dependency. The
published Fedora defects remain until fixed artifacts are released.

The shared runner replaces the Ubuntu-only script. It does not complete the
exhaustive CLI inventory, cold-cache trials, or repeated-guest statistics.

## Run the existing checks

The published-artifact runner requires Bash, GNU coreutils, tar, GitHub CLI access,
and a working Docker or Podman connection. It does not compile OMG.

```bash
./scripts/test-release-smoke.sh
./scripts/release-smoke.sh --release v0.1.218 --distro all \
  --evidence-dir "$HOME/.cache/build-targets/omg-smoke-evidence"
```

The first command uses controlled fixtures. It is not distribution proof.
The second runs downloaded binaries inside disposable containers. It currently
exits nonzero for Fedora. Each invocation owns a unique `run-*` evidence directory.

A real local timeout probe was also run with `--timeout-seconds 1` on Arch search.
It returned `HARNESS_ERROR` with code 124 and verified container absence. A timeout
is an incomplete observation, not a measured product latency or a passing case.

The staged-artifact mode is documented in [scripts/README.md](../scripts/README.md).
Staged and published archives meet at the same checksum validator. Neither mode
makes the historical source-build benchmark below a release benchmark.

## Audit of the historical headline

[Run 20260903_015949-5c43ddcc](records/20260903_015949-5c43ddcc/meta.json)
records an Arch host, kernel 7.2.2, an Intel i9-14900K, 31.1 GiB RAM, and hyperfine
1.20.0. It used three warmups and 20–50 measured runs. The metadata explicitly
records a dirty source tree, including a modified search implementation.

The measured daemon-backed search mean was 13.088 ms, median 11.366 ms, with a
9.588 ms standard deviation. Pacman's mean was 247.384 ms. Dividing those means
produces 18.9016, which explains the old rounded 19× headline.

That ratio does not establish equivalent work. The preflight recorded 6 output
lines for OMG and 458 for pacman search. Merely finding `firefox`
in each output does not prove equal result sets, limits, repository scope, or
formatting work. This is a comparison of those observed invocations, not a fair
search-speed guarantee. The root README no longer promotes that ratio.

The record compares the shipped `omg` CLI invocations. Do not describe a warm daemon
measurement as cold startup. No claim here establishes Debian, Ubuntu, Fedora,
or QEMU performance from this Arch development run.

Historical files remain intact for inspection:

- `records/<id>/` contains hyperfine samples and metadata.
- `records/INDEX.md` indexes historical runs.
- `latest.md` summarizes a historical performance run, not release smoke coverage.
- `summary.json` is the reviewed CI baseline, not proof of platform support.
- `badge.json` may contain a historical headline; it is not a cross-distro claim.

`benchmark-hyperfine.sh --guest` is now the shared four-distribution read-query
driver. It requires a prebuilt `OMG_BENCH_BINARY` and Hyperfine, refuses nonempty
output directories, and measures info, full JSON search, and explicit counts.
There is no automatic substitute timer. The default development mode can still
build from source; do not invoke that implicit build on this shared host.

The recorder's measurement validator recomputes statistics from finite samples
and verifies successful exit receipts. It accepts slower, parity, and sub-1 ms
results. Use `--validate-only --scenario <name>` for scoped measurement checks;
these checks do not establish workload equivalence. The legacy archive/report
writer still assumes daemon labels and recorder-host metadata, so it must not
publish the new guest measurements without further work.

### Cleanup proposals — not deletion authorization

- `benchmark.sh` was retired once `Makefile`'s `bench`/`bench-fast` targets moved to
  `benchmark-hyperfine.sh`. The separate millisecond-rounded Bash timer is gone;
  historical records, raw logs, and archives remain retained.
- Replace the hardcoded arrays and speedup annotations in
  `scripts/generate-benchmark-chart.py` with validated record inputs; rebuild its
  derived images only after the evidence-backed reporting path is verified.
- Review consolidating `.github/workflows/benchmark.yml` orchestration with the
  QEMU workflow. Keep daemon-backed and daemon-disabled profiles distinct rather
  than silently dropping one or combining their results.

No files are deleted by these proposals. Frozen sources, runners, raw logs,
archives, and historical benchmark records remain retained.

## What Oligarchy actually does

The inspiration is [ThePrimeagen/Oligarchy](https://github.com/ThePrimeagen/Oligarchy),
an automation project for testing Omarchy releases. This review pinned its source
to commit `80c44b32a99539ce4ee58133b5bae761e5114e40` rather than relying on a search summary.

Its [QEMU client](https://github.com/ThePrimeagen/Oligarchy/blob/80c44b32a99539ce4ee58133b5bae761e5114e40/src/qemu/client.ts)
uses direct `qemu-system-x86_64` processes, QMP over a Unix socket, a serial log,
UEFI firmware with a per-session variables file, and qcow2 disks. Defaults include
`q35,accel=kvm`, `-cpu host`, two vCPUs, 4 GiB RAM, and `-display none`.
It creates a fresh 40 GiB virtual disk with `qemu-img create`, boots an ISO,
and controls keyboard, mouse, and screenshots through QMP.

The inspected launch function is not a libvirt snapshot manager or an SSH cloud-image
runner. Its QMP capability handshake proves the control connection works, not that
the guest has booted successfully. Its
[driving guide](https://github.com/ThePrimeagen/Oligarchy/blob/80c44b32a99539ce4ee58133b5bae761e5114e40/field-guide/driving.md)
describes exporting guest logs through the serial console. This is useful for
failures where the desktop or network is broken.

Borrow real guest execution, bounded control operations, session isolation, and
serial evidence. Do not copy its default temporary-directory placement onto this
machine's RAM-backed `/tmp`. Do not put an AI-controlled desktop interaction loop
inside the timed region of a CLI benchmark.

## Headless QEMU design for OMG

This is the full proposed acceptance contract. The initial Ubuntu information
runner implements only a subset; the remaining requirements below are not claims
of completed coverage.

1. Use distribution-owned cloud-image catalogs for
   [Arch](https://geo.mirror.pkgbuild.com/images/latest/),
   [Debian](https://cloud.debian.org/images/cloud/bookworm/),
   [Ubuntu](https://cloud-images.ubuntu.com/noble/), and
   [Fedora](https://fedoraproject.org/cloud/download/).
   These are discovery URLs, not pinned inputs. Select an immutable build URL,
   checksum, architecture, release, and firmware mode before execution. Verify
   available publisher signatures independently of the downloaded checksum.
2. Keep the verified base image read-only. Create one external qcow2 overlay and
   one disposable UEFI variables file when required. Record the backing format
   explicitly. Never boot the writable base or reuse a failed test's overlay.
3. Use KVM, two vCPUs, one guest at a time, and a recorded RAM limit. Start at
   2 GiB for a CLI guest; raise it only after measuring a requirement. Keep all
   images, overlays, logs, and caches under `~/.cache/build-targets/omg-release-smoke`.
   No host compilation is required to test downloaded release artifacts. If a
   build is needed, use `-j 2` and do not overlap it with measurement.
4. Use `-display none`, a private QMP socket, and a serial log. Use loopback-only
   SSH forwarding, per-run credentials, and a private known-hosts file. Do not
   expose SSH or QMP on all host interfaces or mount the host home into the guest.
5. Provision cloud-init-capable images with a per-run NoCloud seed and unique
   instance ID. Verify image-specific support rather than assuming every image
   accepts the same seed or default username. Pin the expected SSH host key through
   provisioning or another trusted channel; do not disable host-key checking.
6. Separate readiness stages. QMP handshake, authenticated SSH, completed guest
   initialization, expected `/etc/os-release`, and required services are distinct
   assertions. Check QEMU liveness while waiting. Bound each wait and preserve
   serial output on failure. Do not use a fixed sleep as readiness proof.
7. Copy the exact matching OMG release archive and verify its digest inside the
   guest. Reuse the authoritative command contracts, not a new hardcoded list.
   Run package mutations only in the guest. Reject `OMG_TEST_MODE` in release runs.
8. Prove guest health before adding command families. Check systemd, sudo under
   the intended user, a real PTY, and reboot recovery with a changed boot ID and
   a preserved guest marker. A cloud-init image does not prove ISO installation
   or desktop behavior; those would require separate cases.
9. Stop the specific QEMU process, wait for it to exit, then remove its overlay,
   seed credentials, sockets, and variables file. Verify final absence after
   success, failure, and timeout. Preserve sanitized evidence separately.

The [QEMU invocation reference](https://www.qemu.org/docs/master/system/invocation.html)
documents display, accelerator, CPU, network forwarding, and serial options.
The [qemu-img reference](https://www.qemu.org/docs/master/tools/qemu-img.html)
documents backing files and image formats. The
[NoCloud reference](https://cloudinit.readthedocs.io/en/latest/reference/datasources/nocloud.html)
documents `CIDATA` seeds and instance identity. These references guide the design;
record the installed versions and verify their exact options during implementation.

## Benchmark protocol before publishing new numbers

Measure three separate clocks: guest boot-to-ready, complete smoke-case duration,
and in-guest CLI latency. Do not combine them into a speedup. Run hyperfine inside
the guest, not around an SSH command that adds host transport latency.

For every performance record:

- Record release and executable hashes, guest image hash, kernel, QEMU version,
  KVM availability, CPU model, vCPU topology, RAM, disk configuration, repository
  snapshot hashes, hyperfine version, and exact argument vectors.
- Assert equivalent semantics before timing. Compare normalized package identities
  and counts with equal limits and repository scope. Retain output digests and
  sample outputs. Label non-equivalent operations separately rather than deriving
  a comparative speedup.
- Separate warm CLI, cold process, cold daemon, and cold filesystem-cache scenarios.
  A fresh guest does not guarantee a cold host page cache. Never clear host caches
  to manufacture a cold run on this shared machine.
- For warm read-query publication, use at least three independent fresh-guest
  runs per distro, three warmups, and at least 30 samples within each run. The
  current 20–50-sample read pilot alone does not meet that repeated-guest target.
- For transactions, the selected budget is 20 independently reset samples per
  tool and operation. Each guest contributes one sample, with zero warmups.
  Repository information, installed versions, manual-install reasons, cache
  manifests, and the base image hash are retained. Preflight warms metadata and
  cache files; this is not a cold-cache benchmark.
- Preserve every sample, exit code, mean, median, standard deviation, and range.
  Failed assertions are failures, not fast timings. Do not discard outliers.
- Run one guest and one benchmark at a time. Record host load and available memory.
  Defer performance measurements while other agents compile. Two vCPUs do not
  cap all QEMU or host I/O overhead. Do not mix KVM and software-emulation results.
- Use native backends appropriate to each distro. Report per-distro results;
  do not average unlike package databases into a single cross-Linux speedup.

[Hyperfine's documentation](https://github.com/sharkdp/hyperfine#usage) explains
warmups, preparation hooks, repeated samples, and exports. Warmup and preparation
choices change what is measured and belong in the record.

## Current candidate verification and remaining gaps

The counter-fixed read matrix passed Arch, Debian, Ubuntu, and Fedora: 858
Hyperfine samples across 29 command distributions, with all recorded package
identity, version, name-set, and count checks passing. Each distro also passed
171 executed inventory cases and retained three declaration-only skips. This
proves the frozen candidate and selected cases, not exhaustive CLI behavior or
release speedups. Evidence is retained in local suite `suite-RyC5fb`.

The inventory executor now handles declared argument arrays, prerequisites,
assertions, target and tier selection, and bounded execution. Coverage still
needs to include raw-argument shortcuts outside Clap, runtime behavior, and
credentialed or interactive cases on suitable infrastructure.

`--benchmark-transactions COUNT` adds fresh-overlay install/remove trials to the
same QEMU pipeline. The root Hyperfine driver remains the measurement owner;
`scripts/qemu-transactions.sh` owns VM reset and trial completeness. A one-sample
pilot must pass all four distros before the selected 20-sample matrix starts.
Early pilots exposed evidence-copy permissions and root-owned scratch cleanup;
their failed suite verdicts are retained rather than rewritten as passes.
Transaction schema 2 additionally checks manual-install reasons and retains
repository archives and cache manifests. Earlier schema-1 pilots lack that
contract and remain diagnostic records, not publication evidence.

Historical known-defect expectations are recorded separately from observed
results. Staged candidates and published artifacts are labeled distinctly.
Blocked declarations must never execute first and only be relabeled afterward.
Dependency failures must identify which command was not reached.

A matching SHA-256 sidecar alone does not authenticate a publisher. Archive-member
and signature/provenance checks need their own explicit evidence. Captured shell
traces are not a general secret-redaction implementation. Legacy archive/report
code still needs guest-aware labels, provenance, and single-sample rendering tests
before generating new README claims.

The shared runner installs QEMU tools inside a disposable controller; it does not
install host packages. Use `--print-pins` for the current image references. Native
ARM/macOS coverage remains infrastructure-dependent. Update discovery still needs
a genuinely matched, nonempty fixture; an empty update set is not a speedup result.
Publish only results supported by the retained evidence.

# Development scripts

Utility scripts for development, testing, and CI of the OMG project.

## Quick Reference

| Script | Purpose | Usage |
| -------- | --------- | ------- |
| `check-perf-regression.py` | Verify no performance regressions | `python3 scripts/check-perf-regression.py` |
| `check-docs-alignment.py` | Fail when docs name a command or option the parser does not have | `python3 scripts/check-docs-alignment.py .` |
| `generate-benchmark-chart.py` | Create benchmark visualizations | `python3 scripts/generate-benchmark-chart.py` |
| `extract-release-notes.sh` | Extract release notes for GitHub releases | `./scripts/extract-release-notes.sh` |
| `collect-release-artifacts.sh` | Stage release artifacts for publishing | `./scripts/collect-release-artifacts.sh <version> <artifact-dir> <release-dir>` |
| `debian-smoke-test.sh` | Debian smoke test in a container | `./scripts/debian-smoke-test.sh` |
| `gen-release-notes.sh` | Generate release notes for a version | `./scripts/gen-release-notes.sh <version>` |
| `r2-rollback.sh` | Roll back R2 release artifacts | `./scripts/r2-rollback.sh` |
| `record-benchmark-run.py` | Archive a hyperfine run into `benchmarks/records/` | `python3 scripts/record-benchmark-run.py` |
| `release-smoke.sh` | Smoke-test published or staged archives in distro containers or a native macOS runner | `./scripts/release-smoke.sh --release latest --distro all` |

---

## check-perf-regression.py

**Purpose:** Automated performance regression detection for CI/CD

**Usage:**

```bash
python3 scripts/check-perf-regression.py
```

The script takes no arguments. It reads the baseline from
`benchmarks/summary.json` and the current search time from
`benchmark_results/search.json` (hyperfine export), falling back to
`benchmark_results.json` or `benchmark_report.md`.

**How it works:** Reads Hyperfine JSON output and compares the absolute search mean with two controls. The pacman comparison detects broad search-cost changes. The `omg status` comparison controls for fixed CLI startup, scheduling, and daemon IPC costs on the same runner. A run fails when the available signals regress beyond the default 35% tolerance and their 95% confidence bounds clear the limits. If a control or its distribution data is absent, the remaining signals retain the fail-closed behavior. Missing, unreadable, or corrupt baseline timing also fails closed.

**Used in:** `.github/workflows/benchmark.yml`

---

## check-docs-alignment.py

**Purpose:** Keep documentation honest about the command surface

**Usage:**

```bash
python3 scripts/check-docs-alignment.py .
python3 scripts/check-docs-alignment.py --skip-environment .
```

`src/cli/args.rs` is the source of truth. The script resolves every `omg ...` line in
the markdown files under `docs/` (plus `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`FEDORA-ENGINE.md`, and `GATE-TEST.md`) against the command definitions, including nested
subcommands, aliases, and the global options. It also requires that any `OMG_*`
environment variable named in the docs exists somewhere in the repository, because the
installer and the CI scripts own several of them.

Findings print one per line as `<file>:<line>: <problem>`. Exit status is 1 when
anything fails to resolve, 2 when the repository root or parser cannot be read, and 0
when every reference resolves. Generated and internal files are skipped:
`docs/changelog.md` and `docs/superpowers/**`.

**Tests:** `python3 scripts/test_docs_alignment.py`

**Used in:** manual runs and documentation review, not yet wired into CI.

---

## generate-benchmark-chart.py

**Purpose:** Create visual benchmark comparison charts

**Usage:**

```bash
python3 scripts/generate-benchmark-chart.py
python3 scripts/generate-benchmark-chart.py --data benchmark_results/
python3 scripts/generate-benchmark-chart.py --output docs/assets/
```

**Requirements:** Python 3.8+, matplotlib, pandas

**Output:** PNG charts saved to `docs/assets/benchmark-comparison.png`

---

## extract-release-notes.sh

**Purpose:** Extract release notes from the changelog for GitHub releases

**Usage:**

```bash
./scripts/extract-release-notes.sh
./scripts/extract-release-notes.sh v0.1.204
./scripts/extract-release-notes.sh v0.1.204 > release-notes.md
```

**Used in:** `.github/workflows/release.yml`

---

## release-smoke.sh

**Purpose:** Verify the exact archives users download or stage for release.
The runner validates each archive against its sha256 sidecar, pulls a
digest-pinned distro image, and executes selected release contracts from
`tests/cli_behavior_inventory.tsv` in disposable containers. No retries or
soft passes hide product failures.

**Usage:**

```bash
./scripts/release-smoke.sh --release latest --distro arch
./scripts/release-smoke.sh --release v0.1.223 --distro all --family package
./scripts/release-smoke.sh --release v0.1.223 --staged-dir ./dist --distro all
./scripts/release-smoke.sh --release latest --distro ubuntu \
  --case release-package-search-tree --tier container
```

- `--release` defaults to the latest published, non-draft release. An explicit
  `vX.Y.Z` tag selects one published release.
- `--staged-dir` switches artifact acquisition to local archives. It requires
  an explicit release tag. Staged and published artifacts use the same strict
  checksum validation path.
- `--case`, `--family`, and `--tier` select registry contracts. Phase 2 exposes
  the `package` family and `container` tier. Unknown or empty selections exit
  2 and list valid contract identifiers.
- `--distro` accepts `arch`, `debian`, `ubuntu`, `fedora`, or `all`. A product
  failure on one distribution does not stop the remaining distributions.
- `--distro all` covers the four Linux container distributions. Native macOS
  needs `--distro macos --executor native` and an independent digest pin file
  supplied through `OMG_SMOKE_DIGEST_PIN_FILE`. This mode changes the host's
  Homebrew state; use a disposable macOS runner. `--apt-abi 7` selects the
  Trixie archive and Debian 13 or Ubuntu 26.04 for a Debian or Ubuntu run.
  The default APT ABI is 6.
- `--timeout-seconds` limits each container execution to 300 seconds by default.
  GNU `timeout` is required. A timeout reports `HARNESS_ERROR` with exit code
  124, or 137 if forced termination was needed. Setup failures use code 120.
  Container launch failures also report `HARNESS_ERROR`.
- Every executed case records container-removal output in `cleanup.txt` and
  queries the engine to verify that the case's container is absent. Unverified
  cleanup overrides a passing product result with `HARNESS_ERROR`.
- `--container-engine` defaults to `$OMG_SMOKE_ENGINE`, then `docker`. Missing
  or unavailable infrastructure exits 3. Product failures exit 1. Invalid
  usage exits 2.
- Each invocation creates a timestamped `run-*` directory under the evidence
  base. Each contract writes `transcript.txt`, `probe.sh`, `metadata.txt`, and
  `result.json` there. The run directory also contains the aggregate
  `results.json`. Each result contains `case_id`, `distro`, `result`,
  `exit_code`, `elapsed_seconds`, `expectation`, and `artifact_source`.
  `artifact_source` distinguishes published archives from local staged artifacts.
  Historical `known-defect` expectations never override the observed result.
  A fixed probe passes; a probe that still violates its assertions fails.
  Result values distinguish
  `PASS`, `EXPECTED_REJECTION`, `PRODUCT_FAIL`, `HARNESS_ERROR`, and `BLOCKED`.
  Later invocations never replace prior aggregate or per-case evidence.
- Downloaded archives and extracted binaries use temporary directories under
  `~/.cache/build-targets/omg-release-smoke`, not `/tmp`. The runner removes
  each distribution's temporary directory when that run exits.

### Optional Sentry reporting

`report-smoke-sentry.sh` runs after the coordinator has collected results and each
case has completed cleanup. It reads `~/.config/omg-smoke/sentry.json`, the path
in `OMG_SMOKE_SENTRY_CONFIG`, or `OMG_SMOKE_SENTRY_DSN` when no file is configured.
The DSN is not written to the log. Missing configuration disables reporting.
Reporting requires `jq` and `curl`; failures do not change the original test exit status.

Keep the configuration outside the repository with permissions `600`. Its JSON
object contains a `dsn` string for a hosted Sentry project. Do not put API tokens,
passwords, or a production environment dump in this file.

The reporter sends one failure-summary event per invocation containing only case
IDs, distribution names, result categories, exit codes, elapsed seconds, release,
and run ID. It does not upload stdout, stderr, guest disks, serial logs, credentials,
or arbitrary input fields. `PRODUCT_FAIL`, `HARNESS_ERROR`, and inventory `FAIL`
rows are sent. Other verdicts are not sent as errors. QEMU combines validated
inventory observations with the final lifecycle result in `sentry-results.json`.
Authoritative result files remain unchanged. Full diagnostics stay local.

Input files are limited to 1 MiB. Sanitized failure metadata is limited to
250,000 characters. Oversized reports fail explicitly rather than dropping rows.
Only `release-smoke` and `qemu-matrix` are accepted environment labels.

Transport is bounded to eight seconds, and the coordinator allows at most twelve
seconds for reporting, followed by a two-second kill grace. It does not retry automatically. `reporting.log` records
acceptance or failure without the DSN. HTTP acceptance is not proof that an event
is visible in the project UI. The log records the attempted event ID before
sending. Fingerprints include the release and sorted failure identities, so a
changed failure set can create another issue. This follows Sentry's documented
[grouping by fingerprint](https://docs.sentry.io/platforms/javascript/guides/node/enriching-events/fingerprinting/).
Replay a saved failure report explicitly with:

```bash
OMG_SMOKE_RELEASE=v0.1.223 ./scripts/report-smoke-sentry.sh /path/to/run/results.json
```

Run the network-free coordinator fixtures with:

```bash
./scripts/test-release-smoke.sh
```

The fixture suite checks usage errors, missing and mismatched sidecars,
cleanup after semantic failure, secret redaction, and the result schema. It
uses a controlled fake engine and does not pull images or mutate packages.

**Image provenance:** the digest pins for Arch (`archlinux`), Debian
(`debian:bookworm`), and Fedora (`fedora`) mirror the build container images in
`.github/workflows/release.yml` (`build-arch`, `build-debian`, `build-fedora`).
The Ubuntu pin (`ubuntu:24.04`) mirrors `Dockerfile.ubuntu`.

**Used in:** `.github/workflows/release-smoke.yml`. The workflow remains in
shadow mode and uploads per-case evidence even on failure.

---

## benchmark-qemu.sh

Run all four supported x86_64 guest baselines sequentially. The profiles use Arch
20260901, Debian 12 Bookworm, Ubuntu 24.04, and Fedora 44. Each image has a pinned
checksum. Image signatures are not independently verified by this script.

```bash
./scripts/benchmark-qemu.sh --distro all --staged-dir /path/to/artifacts --benchmark
./scripts/benchmark-qemu.sh --distro ubuntu --release v0.1.223
```

The staged directory must contain the selected distro archives and checksum
sidecars using the canonical names below. Missing staged inputs fail rather than
falling back to published files. Omit `--staged-dir` to download published archives.
The selected release or staged artifacts must still be reviewed against the
artifact-specific evidence before treating a four-guest result as a release
qualification.

Requirements are local Docker access, `/dev/kvm` available to the controller,
`jq`, and GNU coreutils. Benchmarks also require host Python 3 for bounded sample
validation. Published downloads also require `gh`. Docker validates
device access. The script does not compile software or install host packages. Prebuilt
QEMU and SSH tools run inside disposable Debian controllers. Each controller has
two CPUs and a 3 GiB memory limit. Each guest has two vCPUs and 1536 MiB RAM.

Each guest verifies strict SSH host keys, sudo, a changed boot ID after reboot,
its distro identity, package search, installation, installed-version parity with
a native tool, removal, and native absence. Debian and Ubuntu also verify local
archive consent and a local-file install/remove cycle. Tests use disposable guest
state. APT fixtures use HTTPS on Ubuntu, IPv4, bounded network retries, no
translation or desktop indexes, and stopped periodic APT timers. Package signature
validation remains enabled.

Add `--benchmark` to invoke a frozen copy of the root `benchmark-hyperfine.sh`
driver: three warmups and 20–50 fresh-process samples per command, with the daemon
disabled and caches warmed by preflight. It measures package info, untruncated
JSON search, and explicit installed-package counts. Native comparisons include
pacman, both apt-cache and apt, and both RPM and DNF where applicable. Counts use
a common Bash wrapper; native count pipelines include `wc`.

Pre/post checks retain package identities and name sets. `benchmarks/summary.json`
inside each guest evidence directory records workload-equivalence checks, exact
command arguments, and the measurement profile. Different search result sets are
marked non-comparable, not advertised as speedups. Native output can include extra
fields. The host validates sample statistics, exit receipts, requested scenarios,
and command identities. A passing measurement run is not a release speedup claim;
these are warm-cache observations, not cold-cache or repeated-guest statistics.

The experimental transaction profile adds independently reset install/remove
samples to those read checks:

```bash
./scripts/benchmark-qemu.sh --distro all --staged-dir /path/to/artifacts \
  --benchmark-transactions 20
```

This requests 320 sample guest boots, plus preparation and restoration. Start with
`--benchmark-transactions 1` to verify a changed runner before collecting the full
budget. `scripts/qemu-transactions.sh` runs inside the existing controller; do not
invoke it as a host package-management tool. It prepares stopped disk bases,
alternates OMG/native order, and creates a new overlay and boot identity for every
sample. Hyperfine runs inside the guest, with one transaction and zero warmups;
boot, SSH, preflight, and evidence collection are outside its clock.

Transaction schema 2 verifies complete installed package/version and manual-reason
sets before and after. Repository state archives, cache manifests, audit copies,
exact arguments, binary/base hashes, and firmware hashes where applicable are
retained. Metadata queries and cache-file hashing warm caches before timing; these
are not cold-cache measurements. The privileged runtime state stays outside the
unprivileged evidence directory. A root-owned guest marker prevents accidental
host invocation of the transaction driver.

`transactions/summary.json` declares every requested trial before execution.
The host independently rejects missing, partial, failed, or identity-mismatched
coverage. Raw files are under `transactions/trials/<operation>-<tool>-NNN/`.
A successful one-sample pilot is correctness evidence, not a performance claim.

Evidence is retained under `~/.cache/build-targets/omg-qemu-benchmark/`.
An all-distro run produces `suite-*/<distro>/run-*` directories and aggregate
`results.json`. Logs, raw timing samples, archive checksums, repository hashes,
reboot proof, and cleanup receipts remain readable by the operator. Private keys
and guest disks are deleted only after controller absence is verified. If that
check fails, state is retained for recovery and the run fails; active disks are
never deleted to produce a clean-looking result. Product failures and setup
failures remain distinct.
The guest writes its own exit receipt. A missing receipt or a mismatch with the
Docker/SSH exit status is a harness error, not a product failure or a pass.
The optional Sentry reporter runs after timing and cleanup without uploading logs.

The aggregate receipt exists before the first guest starts. It contains four
requested targets throughout the run. `NOT_RUN` means a target has not started.
`INCOMPLETE` means it started but the coordinator has not collected a final result.
Treat either state as unverified, including after interruption. The existing
`test-release-smoke.sh` suite tests these states and QEMU failure handling with a
fake Docker boundary. Those fixtures do not claim to execute guest commands.

Cold-cache benchmarks, repeated-guest statistics, and exhaustive CLI coverage
remain separate work. Passing this runner does not declare that every OMG command
works on every distro. Its Debian guest is Bookworm (APT 6), so that result does
not prove Debian 13 behavior. The release pipeline builds a separate Trixie
(APT 7) archive and smoke-tests it before publication.

## Release Artifact Naming (canonical scheme)

All release pipelines and the installer MUST use this single naming convention.
`.github/workflows/release.yml` produces these assets. `install.sh` selects an
archive by host and APT ABI, then downloads it and its checksum sidecar from
the R2 release domain. GitHub Releases remains a release mirror.

| Platform | Archive name |
| -------- | ------------ |
| Arch Linux | `omg-v<version>-<arch>-linux-arch.tar.gz` |
| Debian (APT 6) | `omg-v<version>-x86_64-linux-debian.tar.gz` |
| Ubuntu (APT 6) | `omg-v<version>-x86_64-linux-ubuntu.tar.gz` |
| Debian 13 / Ubuntu 26.04 (APT 7) | `omg-v<version>-x86_64-linux-debian-trixie.tar.gz` |
| Fedora / unknown Linux distro fallback | `omg-v<version>-<arch>-linux-fedora.tar.gz` |
| macOS | `omg-v<version>-<arch>-darwin.tar.gz` |

- `<version>` is the release tag without the leading `v` (e.g. `0.1.223`).
- Published Linux archives use `x86_64`; macOS uses `aarch64`. Architecture
  detection alone does not mean a release archive exists for that target.
- Debian/Ubuntu selection checks the native APT library ABI. APT 7 uses the
  Trixie pair on either distro; APT 6 retains the distro-specific archive.
- Every archive MUST have a sidecar `<archive-name>.sha256` containing exactly
  one standard `sha256sum` entry. `install.sh` refuses missing, malformed, or
  mismatched sidecars.
- `collect-release-artifacts.sh` rejects duplicate, missing, unexpected, or
  checksum-invalid release files before GitHub publication or R2 upload.
- Any new release pipeline (local or CI) must emit exactly these names plus
  checksum sidecars; do not invent alternate schemes such as Rust target-triple
  names (`x86_64-unknown-linux-gnu`) - the installer will not select them.

---

## Script Conventions

- **Shell scripts:** shebang `#!/usr/bin/env bash`, `set -euo pipefail`, marked `+x`
- **Python scripts:** shebang `#!/usr/bin/env python3`, Python 3.8+
- **Exit codes:** `0` success, `1` general failure, `2` invalid usage, `3` missing dependencies, `4` configuration error. Two scripts predate the convention and keep their codes: `r2-rollback.sh` exits `65` (invalid semver) and `66` (missing R2 object); `debian-smoke-test.sh` exits `127` (no container engine).

---

## Contributing

1. Create the script with a proper shebang.
2. Add usage documentation in docstrings/comments.
3. Make it executable: `chmod +x scripts/your-script.sh`.
4. Add an entry to this README.
5. Test locally before committing.

## Related Documentation

- **[Makefile](../Makefile)** - Common development commands
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribution guidelines
- **[.github/workflows/](../.github/workflows/)** - CI/CD pipelines

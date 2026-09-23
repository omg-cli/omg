---
title: Local QA pipeline
sidebar_position: 62
description: Run release smoke and QEMU guest checks from a checkout
---

# Running the QA pipeline locally

> **Who this page is for:** OMG maintainers and contributors. It documents the local virtual-machine test environment.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

The local scripts let you test a candidate from a checkout without waiting
for hosted CI. The GitHub workflows run the corresponding release smoke and
QEMU paths and retain evidence. Local failures can open issues; the trusted
hosted reporter closes an issue only after a qualifying passing push to
`main`. See [the QA issue loop](./qa-loop.md).

## Prerequisites

- Linux x86_64 with KVM (`/dev/kvm` readable+writable), Docker, `jq`,
  authenticated `gh`, and coreutils. Guests need ~3 GB RAM and several GB
  of image downloads. Container smoke also supports Podman; QEMU uses Docker.
- ARM legs: an aarch64 host with working KVM; a runner label alone does not
  prove `/dev/kvm` is available. KVM
  cannot cross architectures, so x86_64 hosts fail ARM legs closed
  instead of emulating.
- macOS legs: any Mac with Homebrew; no container engine needed
  (`--executor native` runs on the host, which CI keeps disposable —
  locally, know it installs/removes the `tree` probe package).
- One-time: `gh label create qa-failure --description "Automated QA pipeline failures" --color B60205`
  (filing targets this label). Optional Sentry reporting reads
  `~/.config/omg-smoke/sentry.json`, `OMG_SMOKE_SENTRY_CONFIG`, or
  `OMG_SMOKE_SENTRY_DSN` when no file is configured.
  See [reporter configuration](../scripts/README.md#optional-sentry-reporting).

## What to run

### ARM runner configuration

The workflow repository variable `OMG_QEMU_ARM_RUNNER` selects a single runner
label for both the ARM health job and ARM guests. When unset it defaults to
`ubuntu-24.04-arm`. In historical run `34778845877`, the three ARM guest
jobs lacked `/dev/kvm` on that default label. This is evidence about that
run, not the current runner; a label does not establish KVM availability.
Do not configure a replacement label until a matching runner is available.

The selected runner must run native Linux aarch64, provide Docker, Bash,
Python 3, jq and the existing harness prerequisites, and let its job user open
`/dev/kvm` read/write with KVM API version 12. Every runner matching the label
must satisfy this contract: health and guest jobs may land on different
machines. Use disposable isolated runners suitable for executing PR-controlled
code with Docker and KVM access.

The rollout plan is to provision and verify the ARM runner, assign its single
label to `OMG_QEMU_ARM_RUNNER` in repository Actions variables, then manually
dispatch a staged ARM run and inspect the health result and all selected guest
evidence. The checked-in pull-request selection excludes this configurable
runner. This editable workflow condition is not a runner authorization boundary:
before registering self-hosted capacity, restrict which workflows and actors may
use it through runner policy. A pull request can change workflow conditions.
The health job checks architecture, device access and the KVM API before ARM
builds begin. It does not change device permissions or enable emulation. ARM
builds still use the existing hosted CPU runner labels; ARM guest jobs use the
configured KVM runner label and repeat their own device checks. The summary
requires both ARM health and selected guests to succeed. Missing, skipped or
failed selected ARM health cannot produce a passing matrix.

ARM health is independent of x64 jobs. A manually dispatched staged `arch=all` run can therefore
produce x64 evidence while failing visibly for unavailable ARM capacity. A
staged `arch=x64` run requests only x64 coverage and skips ARM health and builds.

### Dispatch and evidence

The hosted `QEMU Matrix` workflow is also a supported verification route when
the workstation has no Linux/KVM environment. Push the candidate to a review
branch, then dispatch that branch with `staged=true`, `distro=all`, and
`arch=all`. Staged jobs build and run library and binary unit tests from the
selected commit before booting guests. Coordinator, issue-filing and reporting
fixtures must pass before guest builds begin. A published-release run checks the
published binaries, not uncommitted workstation changes.

The workflow resolves its tag once, records source and artifact provenance,
and rejects skipped selected guest jobs. Download the per-distro evidence and
inspect inventory skips as well as the final job result. The main CI sandbox
lane additionally requires explicit namespace, isolation and root-handoff
regressions; QEMU lifecycle success is not a substitute for that lane.

Hosted Sentry configuration uses `OMG_SMOKE_SENTRY_DSN` through an environment
variable and a private runner-temporary file. Guest reporting logs show intake
acceptance or failure. A separate `qemu-matrix-workflow` fallback reports failed
builds and other failures before guest reporting can run. Its `ubuntu` distro
identifies the coordinator, not a failed guest; the accompanying context file
contains job outcomes, commit and workflow URL. Missing secrets are visible
notices, and delivery failure never converts failed tests into success.

Pull-request jobs do not receive the Sentry secret. Their evidence artifacts and
CI status remain available; scheduled and manually dispatched runs retain Sentry
reporting. `GH_TOKEN` is limited to release resolution/download and nightly issue
filing. The hosted x86 runner grants KVM access only to its job user through an ACL.

Uploaded QEMU evidence includes diagnostic file types only. Private guest keys,
cloud-init configuration and disks retained after failed cleanup are excluded.

Audit pins without booting anything (fast, always works):

```bash
./scripts/benchmark-qemu.sh --print-pins
```

Fast hermetic gate before any guest (runs the fixture suites):

```bash
./scripts/test-release-smoke.sh
./scripts/test-qa-file-issue.sh
```

Container smoke against your local build (no release needed) — package
exactly like `.github/workflows/release.yml` does, then:

```bash
./scripts/release-smoke.sh --release vX.Y.Z --distro all --staged-dir <dir>
```

Native macOS smoke needs an independent archive digest pin before it can
execute a release binary on the host. Follow the commands in
[macOS release smoke](./qemu-macos.md#run-a-published-archive-locally).

Full QEMU guests (needs KVM + Docker):

```bash
./scripts/benchmark-qemu.sh --distro all --release vX.Y.Z --staged-dir <dir> --inventory-tiers hermetic,container --inventory-allow-mutations
./scripts/benchmark-qemu.sh --arch aarch64 --distro debian --release vX.Y.Z --staged-dir <arm-dir> --inventory-tiers hermetic,container --inventory-allow-mutations  # ARM host only
```

Nightly-equivalent (published release + all safe tiers, x86_64 KVM host):

```bash
for distro in arch debian ubuntu fedora; do
  python3 scripts/prepare-qemu-release.py --tag vX.Y.Z --distro "$distro" --destination "published-$distro"
  ./scripts/benchmark-qemu.sh --distro "$distro" --release vX.Y.Z --release-dir "published-$distro" --inventory-file "published-$distro/cases.tsv" --inventory-tiers hermetic,qemu,container,network,pty --inventory-allow-mutations
done
```

Published runs use the inventory from the release tag's resolved commit, with its
revision and SHA-256 recorded in provenance. Staged builds use the current source
inventory. This avoids testing an older release against commands added later.
The harness still comes from the selected workflow revision. An inventory failure
fails the run and reports its own case; it does not overwrite a passing lifecycle.

The package lifecycle also requires a nonempty privileged audit log and runs
`omg audit verify` against it. Directory modes and verification output are saved
under guest evidence. See [Linux audit storage and migration](security.md#audit-logging).

## What inventory results prove

The current inventory has 196 rows: 176 hermetic-tier contracts, nine
container-tier contracts, and 11 rows in other or combined tiers. The `hermetic`
tier names the fixture-based Rust test contracts. Running these rows in a
real guest is not hermetic: runtime downloads and other network operations
still need network access. Guest images are pinned, but package index refreshes
use live repositories. Saved repository hashes and package versions identify the
observed run, not a promise of identical future repository contents.
Do not report all commands tested when declared,
credentialed, or otherwise gated rows were skipped.

The runner validates the inventory before executing commands. It replays
per-row prerequisite chains in fresh working directories, expands `${ROOT}`
as a literal fixture path, and checks declared JSON and artifact assertions
when the command succeeds. A known defect remains a failure, not a pass.
The guest fixture provides Podman on Fedora and requires no container engine on
the other three images. Container command exit expectations reflect that fixture.
An unexpected engine configuration fails setup rather than changing expectations.
Fedora's `update --fast` and `update --turbo` rows build a two-version RPM in
the disposable guest and temporarily restrict DNF to one local repository.
The fast row begins with stale cached metadata and requires a refreshed upgrade;
the turbo row begins with cached metadata and RPM content. Both require the
native RPM version to change from 1 to 2, a matching DNF upgrade history entry,
and no unrelated installed-package changes. The fixture restores DNF policy and
removes its package after each row. See the [DNF5 cache rules](https://dnf5.readthedocs.io/en/latest/misc/caching.7.html).
The offline daemon row runs first because switching repository policy expires
DNF's warm user cache even after the original policy is restored. The turbo
fixture publishes version 3 after caching version 2, so an online upgrade
cannot satisfy its version-2 oracle.
Gated or failed prerequisites block their dependents. Missing receipts,
transport failures, and empty execution selections fail the harness.

A guest-side supervisor records completed CLI exits separately from executor
exits. A CLI returning 125 is not a timeout-tool failure. Guest-side deadlines
terminate commands independently of SSH. Each row
retains stdout, stderr, prerequisite output, and a completion receipt under
`inventory/rows/`. `inventory/input-sha256.txt` identifies the runner and TSV.
`inventory/metadata.json` records the binary path, tiers, deadlines, and opt-ins. Existing inventory evidence cannot be overwritten.
Working directories and installed runtime state disappear with the guest;
only cwd-local fixtures are isolated per row, not the guest's home directory
or package database. Native ARM and macOS results require their own runners.

## Evidence contracts and sources

- [GNU timeout](https://www.gnu.org/software/coreutils/manual/html_node/timeout-invocation.html)
  defines exit 124 for a deadline, 125 for a timeout-tool failure, and 126 or 127
  for invocation failures. Exit 137 alone does not identify what received SIGKILL
  or prove an out-of-memory event. Guest receipts and cleanup evidence are needed
  in addition to the transport exit.
- [OpenSSH exit status](https://man.openbsd.org/ssh#EXIT_STATUS) returns the remote
  command status, or 255 for an SSH error. The runner therefore requires a guest
  completion receipt before accepting a product exit.
- [Podman exec exit status](https://docs.podman.io/en/latest/markdown/podman-exec.1.html#exit-status)
  uses 125 for Podman errors. The missing-container fixture on Fedora returns
  that status through OMG. The guest supervisor distinguishes it from a
  timeout-tool failure with the same number.
- [GitHub release assets](https://docs.github.com/en/rest/releases/assets#get-a-release-asset)
  expose a `digest` field. The Python installation row uses 3.12.14 from
  [PBS release 20260901](https://github.com/astral-sh/python-build-standalone/releases/tag/20260901),
  whose standard x86_64 GNU/Linux archive has digest
  `sha256:936c246dfdbbfa7cb22dd01814a21f582a892689fae96b06071a5e433baffa22`.
  This identifies the observed asset, not a guarantee that future assets have digests.
- [Sentry fingerprints](https://docs.sentry.io/platforms/javascript/guides/node/enriching-events/fingerprinting/)
  control issue grouping. Local `reporting.log` proves an attempted event ID and
  HTTP intake acceptance or failure. Indexed visibility requires looking up that
  event ID in Sentry. See [reporter limits](../scripts/README.md#optional-sentry-reporting).

These references define tool contracts. A passing OMG claim additionally needs
its frozen runner and inventory hashes, artifact checksum, guest identity,
selected row results, and completion receipt. A documentation citation is not
execution evidence.

## Filing issues (and the coming PRs) from a local run

`benchmark-qemu.sh` and `release-smoke.sh` attempt to file local failures
themselves and write `issue-filing.log`. A local pass does not close a hosted
issue. If that filing failed, inspect the log and dry-run the helper before
retrying. For QEMU, use `sentry-results.json` when present because it includes
inventory failures as well as the lifecycle result; `results.json` alone is
only the lifecycle row. Use a unique run URL so a repeat failure comments:

```bash
RUN_URL="local-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)"
./scripts/qa-file-issue.sh <run-dir>/sentry-results.json --run-url "$RUN_URL" --source qemu-matrix --failures-only --dry-run
./scripts/qa-file-issue.sh <run-dir>/sentry-results.json --run-url "$RUN_URL" --source qemu-matrix --failures-only
```

Notes:

- `--repo` defaults to your checkout's repo via `gh repo view`
  (forks file to the fork); override with `--repo owner/name`.
- Evidence dir defaults to the results file's directory; excerpts come
  from transcripts / `guest-check.log` / inventory row logs.
- Closing requires `--fixed-by-pr N` for a pushed pull request whose
  commit passed. The trusted reporter adds that flag when GitHub
  associates the passing commit with a pull request. A direct push does
  not close. See `docs/qa-loop.md`.
- Fingerprints are shared between local and CI runs (same `--source`
  names), so a CI nightly and your local run update the same issues
  instead of duplicating them.

## Opening fix PRs from [qa] issues (opt-in, drafts only)

Nothing opens PRs unless you run this. From a clean tree with your fix
committed on a branch:

```bash
./scripts/qa-open-pr.sh --issue 123 --branch fix/search-tree-arch --dry-run
./scripts/qa-open-pr.sh --issue 123 --branch fix/search-tree-arch
```

The script refuses non-`[qa]` issues, closed issues, dirty trees, and
unknown branches; then pushes the branch and opens a **draft** PR with
`Fixes #123` plus a verification checklist. Verify per the checklist,
promote from draft, and merge. The issue stays open until a passing run
of that pushed commit closes it. A local pass does not.

## Evidence map

- Release smoke: `<evidence-base>/run-*/<distro>-<case>/{transcript.txt,metadata.txt,probe.sh,result.json}`, aggregate `results.json`.
- QEMU: `<root>/run-*/{guest-check.log,guest/evidence/,inventory/{results.json,rows/*.log},metadata.txt,kvm-probe.log,results.json}`.
- Suites: `<root>/suite-*/results.json` aggregates per-distro runs.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `KVM device /dev/kvm is missing` | No KVM here; run on a KVM host. Never bypass with `OMG_QEMU_ALLOW_NO_KVM=1` outside tests. |
| `guest arch aarch64 needs a aarch64 host` | Cross-arch emulation refused by design; use an ARM host. |
| `no published aarch64-linux archives` | ARM legs need `--staged-dir` with arm64-native builds. |
| `no aarch64 cloud image pinned for arch` | Upstream publishes no ARM Arch image; arch is x86_64-only. |
| `container engine … not found` / `info failed` | Start Docker (or pass `--container-engine podman`). |
| `gh: Requires authentication` | `gh auth login`; filing and published downloads need it. |
| `Sentry reporting disabled` | Set `OMG_SMOKE_SENTRY_DSN` or ignore (results are unaffected). |
| `invalid identifier` inventory row | Bad TSV case id; fix the row — it fails loud, never executes. |

## First run-through checklist (feeds the error audit)

1. `--print-pins` + all fixture suites green (`test-release-smoke`,
   `test-qa-file-issue`, `test-qa-open-pr`, `test-qa-audit`).
2. Container smoke on your build, all four distros.
3. QEMU guests per distro with `--inventory-tiers hermetic,container --inventory-allow-mutations`.
4. Inspect each `issue-filing.log`. If local filing failed, dry-run a manual
   retry, review it, then file for real.
5. Summarize what failed for the audit — paste-ready, secrets scrubbed:

```bash
./scripts/qa-audit.sh ~/.cache/build-targets/omg-qemu-benchmark --tsv tests/cli_behavior_inventory.tsv
./scripts/qa-audit.sh target/release-smoke
```

Bring that output back: it is the input to the code/command audit —
no pending-row flips, no expectation edits, just errors.

## Where to go next

- [QA issue loop](./qa-loop.md) explains when an issue opens or closes.
- [QEMU image review](./qemu-image-renewal.md) covers image provenance expiry.
- [Release readiness](./release-readiness.md) lists the publication gates.

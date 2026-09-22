---
title: macOS release smoke
sidebar_position: 63
description: Run macOS package smoke tests on a native runner
---

# macOS release smoke

OMG runs macOS release smoke directly on a disposable Apple Silicon host. It does not boot a macOS guest under QEMU. This page explains why and shows the exact native runner requirements. It is for maintainers; new users should start with [getting started](./getting-started.md).

## Why this lane is native

The project's macOS release archive targets `aarch64-darwin`. Apple licenses macOS virtualization on Apple-branded computers, and GitHub says its hosted macOS runners do not support nested virtualization. The repository therefore uses the hosted `macos-14` runner directly. [Apple's macOS license](https://www.apple.com/legal/sla/) and [GitHub's hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) are the current external sources for those constraints. Check the license for the macOS version you use before designing a new VM lane.

The runner executes package probes on the host. It resets the `tree` probe package with `brew uninstall tree || true` and can install or remove it during a test. A local run changes your Homebrew state. Use a disposable Mac or review that effect before running.

## Current CI path

The `smoke-macos` job in `.github/workflows/release-smoke.yml` runs on `macos-14`. It installs GNU coreutils for `gtimeout`, pins the release archive to GitHub's server-computed asset digest, and runs:

```bash
./scripts/release-smoke.sh --release "$RELEASE_TAG" --distro macos --executor native
```

The job supplies `OMG_SMOKE_DIGEST_PIN_FILE`. Native mode refuses to start without this independently recorded digest. For a published archive, the runner also verifies its release attestation before extraction. The archive's own `.sha256` sidecar alone cannot establish the trusted digest if both archive and sidecar change.

The job uploads `release-smoke-macos` evidence using the same `results.json` schema as container smoke. `scripts/test-release-smoke.sh` covers the native mode with fake `brew` and `omg` binaries, including failure cases and the `shasum`/`gtimeout` fallbacks. Those fixtures do not prove a published archive passed on a real Mac.

## Run a published archive locally

On an Apple Silicon Mac with Homebrew, `gh` authentication, GNU coreutils,
`jq`, and a disposable Homebrew state, resolve the latest published tag. The
pin file must contain the GitHub asset digest for the exact archive.

```bash
TAG="$(gh release view --repo omg-cli/omg --json tagName --jq .tagName)"
gh api "repos/omg-cli/omg/releases/tags/$TAG" \
  --jq '.assets[] | select(.name | endswith("-aarch64-darwin.tar.gz")) | "\(.digest | sub("^sha256:"; ""))  \(.name)"' \
  > smoke-digest-pins.txt
```

Check that the file contains one 64-character SHA-256 digest and the expected archive name. Then run the smoke test:

```bash
OMG_SMOKE_DIGEST_PIN_FILE="$PWD/smoke-digest-pins.txt" \
  ./scripts/release-smoke.sh --release "$TAG" --distro macos --executor native
```

For a staged archive, use `--staged-dir DIR` with an explicit tag and a digest recorded independently of that staged directory. Keep the pin file and `results.json` with the release evidence.

## Limits and next steps

- `--distro all` covers Linux container images. It does not include macOS.
- `--executor native` only pairs with `--distro macos`.
- The native lane tests selected package contracts. It does not establish parity for every OMG command, runtime, or Homebrew state.
- The shared probe inventory names container distros, so native macOS cases use a baseline pass expectation. Read the observed case results and transcript before claiming success.

See [release operations](./release-operations.md) for publication, [scripts](../scripts/README.md) for smoke options, and [QA loop](./qa-loop.md) for filing failures.

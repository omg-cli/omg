# macOS guests: verdict and path

> **Who this page is for:** OMG maintainers and contributors. It documents the macOS virtual-machine notes.
> It is not an everyday user guide. If you are new to OMG, start with
> [Getting started](./getting-started.md).

## Verdict

No macOS-on-QEMU in CI. Apple's EULA permits macOS virtualization only on
Apple-branded hardware, so Linux-hosted macOS guests (OSX-KVM and kin) are
out for this project — legally, not technically.

Tart (the state-of-the-art Apple-silicon VM manager) does not help on
hosted runners either: it needs an Apple Silicon host with nested
virtualization, which GitHub-hosted `macos-*` runners (themselves VMs) do
not provide. Tart is viable only with self-hosted Mac hardware or a paid
managed-VM service (e.g. Cirrus), neither of which this project has.

## Recommended path: native smoke on GitHub-hosted macOS runners

GitHub-hosted `macos-14`/`macos-15` runners are fresh ephemeral VMs per
job — the isolation property QEMU buys on Linux already holds there. No
guest layer is needed.

### Status: implemented

- `scripts/release-smoke.sh` has `--executor container|native` plus a
  `macos` distro (`--distro macos` requires `--executor native` and vice
  versa). Native cases reset the shared probe package
  (`brew uninstall tree || true`), then run the same probes against the
  `aarch64-darwin` archive with `OMG_PROBE_ROOT` pointing at the staged
  dir. Metadata records `image=native-host`, `engine=native`, and
  `expectation=pass` (the inventory targets name container distros only,
  so a native run establishes the baseline).
- macOS toolset fallbacks: `TIMEOUT_BIN` selects `timeout` or `gtimeout`
  (coreutils), `SHA256_BIN` selects `sha256sum` or `shasum -a 256`.
- `scripts/report-smoke-sentry.sh` accepts `distro: macos` and prefers
  `uuidgen` (macOS) with a `/proc` fallback (Linux).
- Harness proof: `scripts/test-release-smoke.sh` covers stub-`brew` +
  fake-`omg` tarballs (pass, bad-search, bad-version), pairing
  rejections, and a restricted-PATH `macbin` run proving the
  `shasum`/`gtimeout` fallbacks.
- CI: the `Smoke macos (native)` job (`macos-14`) in
  `.github/workflows/release-smoke.yml` runs
  `./scripts/release-smoke.sh --distro macos --executor native` and
  uploads `release-smoke-macos` evidence in the same `results.json`
  schema, so Sentry reporting, issue filing, and dashboards work
  unchanged.

Prior gap analysis (now closed):

- `scripts/release-smoke.sh` executes every case inside a digest-pinned
  distro container (`--container-engine docker|podman`). macOS runners
  ship no Docker daemon.
- The fix is a native executor mode: run the TSV-selected cases directly
  on the (disposable) runner with hermetic dirs, keeping the same
  results.json evidence schema so Sentry reporting, issue filing, and
  dashboards work unchanged.
- The OMG side is ready: the `macos` Cargo feature (Homebrew backend)
  exists, and `macos-14` already runs CI in `.github/workflows/ci.yml`.

## Non-goals

- OSX-KVM / macOS-Simple-KVM on Linux hosts (EULA).
- Tart on hosted runners (no nested virt).
- Colima-as-Docker on macOS runners (heavy, flaky; native mode is simpler
  and the host is already disposable).

## Sources

- Apple hardware-only virtualization: Apple EULA / compliant-supplier
  guidance, e.g. https://www.accio.com/plp/mac-os-virtual-machine-online
- Tart needs Apple Silicon + no nested virt on CI runners:
  https://github.com/suzuke/agend/blob/HEAD/e2e/README.md,
  https://github.com/netwindhq/gha-outrunner/blob/HEAD/docs/tutorial/tart-macos.md
- ARM runners free for public repos (for the Linux side of the matrix):
  https://github.blog/changelog/2025-08-07-arm64-hosted-runners-for-public-repositories-are-now-generally-available/

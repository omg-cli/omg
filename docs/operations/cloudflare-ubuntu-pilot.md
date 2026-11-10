# Ubuntu Cloudflare CI pilot

This pilot tests Ubuntu 24.04 userspace directly in a disposable Cloudflare Container. QEMU, native platform, security, coverage and release checks remain required. A pilot receipt does not establish full replacement coverage.

## Resource and trust boundaries

The pilot uses the existing Sandbox 0.12.14 and CI 0.2.0 engine. Its Worker, Workflow, container application, authentication secret and private evidence bucket are separate from production portable CI. `CI_WORKLOAD=ubuntu-native-pilot` selects a fixed deployment-owned plan. Requests remain restricted to exact OMG source commits on the main ref. Repair and test-audit proposals are rejected.

The plan runs locked Cargo dependency preparation, source formatting and `ubuntu-native-readonly`. Candidate commands retain UID/GID 10001, the existing output limit and bounded command deadlines. The trusted image contains both native Python oracles. Their bytes, runner files and toolchain inputs are verified during image publication.

Cloudflare documents the [standalone Sandbox binary on an arbitrary base image](https://developers.cloudflare.com/sandbox/sdk/configuration/dockerfile/#using-arbitrary-base-images) and [matching image/package versions](https://developers.cloudflare.com/sandbox/sdk/concepts/sandboxes/#version-compatibility). The Dockerfile pins the Ubuntu 24.04 amd64 manifest and the existing Sandbox, Rust, Node and Bun versions. This is not an SDK migration.

## Check runtime compatibility first

`wrangler.ubuntu-pilot.jsonc` is the separate short-lived capability gate. It uses the existing production image, which currently reports Ubuntu 22.04. That gate does not certify the new Ubuntu 24.04 image.

Its only authenticated command tests owned scratch, ownership changes, UID/GID switching, controller-file protection and process-group cleanup. Success requires confirmed destruction. A durable absolute three-minute deadline fences late starts and retries failed destruction within a bounded window.

Use [SDK 0.x command timeouts](https://developers.cloudflare.com/sandbox/sdk/api/commands/#exec) with explicit destruction. A command timeout can close the caller connection while the process continues. The capability gate keeps its caller timer outside the Durable Object RPC because its selected runtime does not serialize `AbortSignal` arguments.

The first hosted gate passed these isolation checks and returned `destroyed: true`. Provider instance readback showed both probe instances inactive. That result proves the existing image's boundary; the Ubuntu image still needs its own smoke and hosted workload.

## Build and publish the Ubuntu image

The manual `ubuntu-image` task in `cloud-ci.yml` builds the reviewed source using the existing GitHub production environment credentials. It publishes only `omg-cloud-ci-ubuntu-pilot:<source-sha>`. It does not deploy a Worker or change production image pins.

```bash
gh workflow run cloud-ci.yml --repo omg-cli/omg --ref YOUR_REVIEWED_BRANCH -f task=ubuntu-image
```

The builder refuses a nonmanual run, another repository, a stale checkout SHA or dirty source. It archives the exact commit, requires digest-pinned base images and verifies the frozen files inside the image. Its local image smoke checks Ubuntu 24.04, amd64 and the candidate identity boundary. It then publishes through Wrangler and joins the raw registry manifest, config digest and local repository digest. Retain the `ubuntu-image-<run>-<attempt>` proof artifact.

This follows Cloudflare's [CI image build/push guidance](https://developers.cloudflare.com/containers/guides/image-management/#push-images-with-ci) and [digest inspection guidance](https://developers.cloudflare.com/containers/guides/image-management/#get-the-digest-of-a-pushed-image). The existing Workers Builds-only publication guard remains unchanged.

Deploy the dedicated pilot only after admitting the published digest and setting matching image/verifier pins. Match class exports, container definitions and namespace bindings as required by [Wrangler Container configuration](https://developers.cloudflare.com/containers/configuration/wrangler/). Store its bearer token as a [Worker secret](https://developers.cloudflare.com/workers/configuration/secrets/), never as a plain variable or image environment value. Verify the actual deployed configuration and [rollout state](https://developers.cloudflare.com/containers/configuration/rollouts/) before starting a workload.

## Execute and admit native behavior

The operator scripts select only the fixed pilot endpoint when `OMG_CI_WORKLOAD=ubuntu-native-pilot`. Their dedicated service configuration is `~/ci/omg-cloud-ci-ubuntu-pilot.json`, with `endpoint`, `tokenFile` and the admitted `imageDigest`. Production selection stays unchanged.

```bash
export OMG_CI_WORKLOAD=ubuntu-native-pilot
bun scripts/cloud-ci-mirror.mjs "$SOURCE_SHA"
bun scripts/run-cloud-ci.mjs "$SOURCE_SHA" main "$RUN_ID" "$ATTEMPT" "$RECEIPT_FILE"
```

The pilot builds both release binaries with `--no-default-features --features debian,pgp,license --locked --offline`. It verifies the production release profile, both binary identities and two exact executed Debian parser tests. It compares the complete installed/manual package set with native APT/dpkg state. The existing daemon oracle requires a populated native catalogue, direct/daemon info agreement, real metrics increments, socket permissions, clean signal shutdown and unchanged package state.

The server validates `ubuntu-native.json` and `ubuntu-daemon.json`. The operator independently downloads the named logs/reports, verifies their hashes and validates the native report joins. Matching hashes alone cannot turn failed behavior into accepted evidence. Failed, empty, missing, wrong-source, wrong-image and wrong-plan evidence must remain failures.

Keep caches and evidence in the dedicated private bucket. Follow [R2 lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) and [private bucket access](https://developers.cloudflare.com/r2/buckets/public-buckets/). The initial compiler cache remains a separate trusted-main-only R2 cache; it is not an untrusted PR shared write cache.

## Replacement decision

Before replacing QEMU, compare the same source through both paths, demonstrate rejection of a controlled bad result, verify native state isolation and confirm no active owned compute remains. Track elapsed time, cache behavior and resource usage separately from successful behavior assertions. Follow [Sandbox lifecycle and destruction](https://developers.cloudflare.com/sandbox/sdk/concepts/sandboxes/#destruction).

Fresh Containers do not prove real distro reboot, kernel, systemd boot integration or block-device recovery. Keep a VM check for any of those accepted product requirements. Retire the QEMU requirement only after its replacement coverage is reviewed and passes on main.

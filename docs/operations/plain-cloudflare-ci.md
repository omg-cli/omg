# Plain Cloudflare runtime pilot

OMG uses GitHub CI for builds, lint, coverage, native-host tests and QEMU acceptance. Cloudflare supplies the private compiler cache and an optional Ubuntu runtime pilot. Codex stays local. The pilot runs automatically on its development branch and can be dispatched manually on main.

## Retired automation

The GitHub workflows `ai-review.yml`, `ai-fix-review.yml`, `ci-orchestration.yml` and `cloud-ci.yml` are disabled. Public and preview endpoints are disabled for `omg-ci-inspector`, `omg-ci-coder`, `omg-cloud-ci`, `omg-artifacts-ci-pilot`, `omg-cloud-ci-capability-pilot` and `omg-cloud-ci-ubuntu-pilot`. All six had empty cron schedules and no custom domains when checked on November 10, 2026. The three former production service configurations also disable those URLs on future deployments.

The dashboard confirms builds are disabled for the three Git-connected legacy Workers, with no deploy hooks. The experimental Workers and fresh runner have no Git connection. Their cron, queue and email trigger sections are empty.

The legacy Sandbox application and both experimental container applications were deleted after every instance was confirmed inactive; all three subsequently returned HTTP 404. R2 and Durable Object owner data were preserved. The abandoned SDK pilot source is saved under Git tag `recovery/retired-sandbox-pilot-20261110`. These changes affect OMG CI, separate from the website, SaaS Workers and other projects.

## Build on GitHub, verify runtime on Cloudflare

`services/ci` uses the native Durable Object Container API and one built-in Workflow step. Its immutable input is a source commit, run ID and attempt. It has no Sandbox SDK, `@cloudflare/ci`, OpenCode, model, issue publisher or PR repair dependency.

1. GitHub builds a multistage image with Rust 1.95.0 and the exact source. The unchanged release profile retains fat LTO and one codegen unit. The recipe verifies both release binaries, both exact release-library tests, native inventory and daemon catalogue before exporting artifacts.
2. The final Ubuntu 24.04 image contains the two binaries, their actual release test executable, manifest, accepted build receipt and frozen oracles. Source, compiler, release profile and all three executable hashes are bound by the manifest. Rust and build tools remain in the builder stage.
3. A fresh Docker container must pass the complete runtime recipe offline before publication. GitHub independently measures the manifest hash, pins the published image digest, and waits for exact application details, completed rollout and healthy capacity.
4. Cloudflare runs both exact tests, CLI checks, complete native inventory and daemon catalogue/socket/metrics/shutdown checks offline. Its receipt must match the independently measured image manifest, source and image digest. Raw log hashes, terminal Workflow completion and confirmed whole-container destruction are also required.

Candidate processes use UID/GID 10001, cleared capabilities and no new privileges. Artifacts and oracles remain owned by root and protected from candidate writes. API, GitHub and R2 credentials never enter the container. Output and execution deadlines remain bounded.

Use the **default scheduling policy**: Cloudflare documents that `durable_object` grants root capabilities even to other UIDs. [Native Container API](https://developers.cloudflare.com/containers/api/durable-object-container/)

The entrypoint is `sleep infinity`; commands use native argv execution. Both output streams are drained concurrently. Killing one process does not guarantee descendant cleanup, so acceptance requires destroying the whole container. [Execute commands](https://developers.cloudflare.com/containers/guides/execute-commands/)

Worker deployment can finish before image rollout. Readiness uses the exact application's detail endpoint after ID discovery, with a ten-minute preparation bound. Candidate execution retains its separate deadline. [Image management](https://developers.cloudflare.com/containers/guides/image-management/), [Rollouts](https://developers.cloudflare.com/containers/configuration/rollouts/), [Application details](https://developers.cloudflare.com/api/resources/containers/subresources/applications/methods/get/)

The Workflow makes one execution call without automatic command retries. Private R2 evidence expires after 30 days; incomplete multipart uploads expire after one day. [Workflow limits](https://developers.cloudflare.com/workflows/reference/limits/), [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [Object lifecycles](https://developers.cloudflare.com/r2/buckets/object-lifecycles/)

## Observed evidence and limits

The first cold GitHub R2 compiler-cache run hit its 40-minute cap. The following warm Portable Rust job passed in 21 minutes 32 seconds, with 1,876 Rust hits and 10 misses, three assembler cache errors and zero cache write errors. Their exact cause and cold-run completion remain unresolved. [Cache receipt](../benchmarks/github-portable-r2-warm-2026-11-10.json)

The hosted native API canary passed on Ubuntu 24.04: UID/GID 10001, zero effective capabilities, protected-file write denial and confirmed destruction. Its short Workflow accepted a configured 45-minute step envelope; this was not a 45-minute duration test. [Canary receipt](../benchmarks/cloudflare-native-api-canary-2026-11-10.json)

Compilation inside Cloudflare did not finish both release binaries within 1,200 seconds on standard-4. Cleanup succeeded. Prior release-build samples completed in 520.53 seconds on GitHub and 337.02 seconds locally. The Cloudflare result is an incomplete lower bound under different host conditions; it does not identify the cause of slower execution. Compilation therefore moved to GitHub while preserving release settings. [Timeout receipt](../benchmarks/cloudflare-release-build-limit-2026-11-10.json), [Prior comparison](../benchmarks/local-vs-github-2026-11-10.md)

The split passed its first hosted run at source `b58aba89602b5bbdbfd5e2a700cfa9f417470b9b`. GitHub built and verified the release artifacts, passed the complete runtime recipe in an offline Docker container, published the pinned image, and deployed it. Cloudflare then passed the permission canary and both exact tests, matched all 94 explicitly installed packages, and checked the daemon against 88,451 native catalogue entries. Both Workflows completed, candidate cleanup and container destruction were confirmed, and a separate provider readback found the instance inactive. The full job took 19 minutes 16 seconds; the hosted runtime step took 32 seconds. These are one-run observations, not a controlled speed comparison. [Hosted run](https://github.com/omg-cli/omg/actions/runs/42888307045), [Compact receipt](../benchmarks/cloudflare-runtime-pilot-2026-11-10.json)

This proves the selected Ubuntu 24.04 amd64 recipe. QEMU, native-host, coverage and release gates remain required. Containers do not prove guest boot, kernel, block-device behavior, package mutations or other distributions. No Cloudflare speed advantage or QEMU replacement is claimed.

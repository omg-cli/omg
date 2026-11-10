# Plain Cloudflare CI pilot

As of November 10, 2026, OMG is retiring the autonomous Cloudflare issue, PR and AI repair system. Ordinary GitHub CI remains required. The replacement Ubuntu pilot runs builds and tests only. Codex stays local.

## Retired automation

The GitHub workflows `ai-review.yml`, `ai-fix-review.yml`, `ci-orchestration.yml` and `cloud-ci.yml` are disabled. The public and preview endpoints of `omg-ci-inspector`, `omg-ci-coder`, `omg-cloud-ci`, `omg-artifacts-ci-pilot`, `omg-cloud-ci-capability-pilot` and `omg-cloud-ci-ubuntu-pilot` are disabled. All had empty cron schedules when checked.

The legacy Sandbox application and both experimental container applications were deleted after all their instances were confirmed inactive. Each application subsequently returned HTTP 404. Stored R2 data and Durable Object data were preserved. The abandoned pilot source is saved under Git tag `recovery/retired-sandbox-pilot-20261110`.

These are separate from the website, SaaS Workers and other projects. Do not re-enable the old workflows or redeploy their service configurations.

## Replacement boundary

The implementation in `services/ci` uses a native Durable Object Container API and one built-in Workflow step. It has no Sandbox SDK, `@cloudflare/ci`, OpenCode, model, issue publisher or PR repair dependency. GitHub supplies an immutable source commit, run ID and attempt. The container downloads the fixed public OMG repository at that commit and executes the frozen recipe.

The controller stays root inside the disposable container and runs candidate code as UID/GID 10001, with cleared capabilities and no new privileges. API, GitHub and R2 credentials never enter the container. A combined output limit, absolute deadline and whole-container destruction bound each run. Success requires verified source/image identity, real selected test executions, complete native inventory and daemon evidence, matching log hashes and confirmed container destruction.

Use the **default scheduling policy**: Cloudflare documents that the `durable_object` policy grants root capabilities even to other UIDs. [Native Container API](https://developers.cloudflare.com/containers/api/durable-object-container/)

The image entrypoint is `sleep infinity`. Commands use the native argv API without an HTTP control server, FUSE mount or SDK process pool. Both output streams are drained concurrently. Killing a process alone does not guarantee descendant cleanup, so the whole container is destroyed before acceptance. [Execute commands](https://developers.cloudflare.com/containers/guides/execute-commands/)

The image is pinned by its registry digest. Deployments must inspect the actual running image because application rollouts can temporarily serve the prior image. [Image management](https://developers.cloudflare.com/containers/guides/image-management/), [Rollouts](https://developers.cloudflare.com/containers/configuration/rollouts/)

The Workflow makes one execution call with no automatic command retry. Its step waits for the container job and returns small evidence references. Raw evidence lives in a private R2 bucket with 30-day expiry and one-day multipart cleanup. [Workflow limits](https://developers.cloudflare.com/workflows/reference/limits/), [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/), [Object lifecycles](https://developers.cloudflare.com/r2/buckets/object-lifecycles/)

## Acceptance

Run the short native API canary before the real Ubuntu Rust recipe. A Docker smoke check, configuration deployment or canary is not a replacement for the actual CLI test job. QEMU, native-host, coverage and release gates remain required. Containers do not prove guest boot, kernel or block-device behavior.

The first cold GitHub R2 compiler-cache run reached its 40-minute job cap. The following warm Portable Rust job passed in 21 minutes 32 seconds, with 1,876 Rust hits and 10 Rust misses. It recorded three assembler cache errors and zero cache write errors. Their cause is not diagnosed. This establishes cache operation and a successful warm job, not a controlled Cloudflare-versus-GitHub speed comparison. [GitHub job and cache receipt](../benchmarks/github-portable-r2-warm-2026-11-10.json)

The locally submitted hosted native API canary passed after provider capacity became ready. Its Ubuntu 24.04 process ran as UID/GID 10001 with zero effective capabilities, could write its owned directory, could not write a root-owned file, and had confirmed whole-container destruction. The built-in Workflow completed with its configured 45-minute step envelope. This was a short test, not a 45-minute duration test. [Canary receipt](../benchmarks/cloudflare-native-api-canary-2026-11-10.json)

The first submission failed before execution because no container instance was available. It remained failed and confirmed cleanup. Deployment now needs a provider readiness check before submitting a job; configuration health alone is insufficient.

The canary used an existing digest-pinned Ubuntu image with its entrypoint overridden through the native API. No Sandbox or CI SDK methods ran. The fresh plain image, full Rust pilot acceptance and performance remain unproven until their retained receipts are recorded here.

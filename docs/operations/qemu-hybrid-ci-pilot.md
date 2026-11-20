# Hybrid CI and QEMU performance pilot

Automatic x86 guests now wait for their own native release pair before
allocating their KVM runner. Fedora additionally depends on the reviewed SQLite
supply. Readiness is scoped to the current CI run and attempt, including the
existing guarded recovery of a successful carried producer. The KVM job still
admits the complete artifact and recipe. The native matrix, both QEMU partition
summaries, and every other required result still feed CI Success.

## Measured baseline

The [#1058 run](https://github.com/omg-cli/omg/actions/runs/44313803542#artifacts)
provides an observational baseline. The first interval includes runner queueing
and is an upper bound on the scheduling savings.

| Distro | Artifact upload to guest start | Guest body | Publisher transfer |
| --- | ---: | ---: | ---: |
| Arch | 10m02s | 7m37s | 4s |
| Debian | 8m04s | 8m58s | 6s |
| Debian Trixie | 12m06s | 10m34s | 5s |
| Ubuntu | 14m40s | 12m22s | 5s |
| Fedora | 14m57s | 12m13s | 12s |

Compare artifact upload, readiness completion, guest start, guest completion
and final required status for each distro. Separate runner wait from execution.
For promotion, run warm and cold repetitions with the same source, image pins
and test identities. Record medians, ranges, all results and hosted runner
minutes. Use enough samples before reporting a tail percentile. Additional
readiness jobs also consume runner slots. [GitHub limits](https://docs.github.com/en/actions/reference/limits)

## Private R2 transfer pilot

I mirrored the Debian Trixie x86_64 image pinned by this branch. The original
341,180,416-byte image is stored as two equal uncompressed parts under its
publisher SHA-512 digest in the private
`omg-qemu-image-pilot-20261118` R2 bucket. A verified lifecycle rule expires
the objects after seven days. The parts fit Wrangler's single-request size
limit. Required CI still uses its existing publisher and cache paths.

On Windows, each trial used fresh files on C:. The publisher path uses curl.
The mirror path uses two parallel authenticated Wrangler 4.163.0 reads and
ordered assembly. Both paths include final verification with
`scripts/verify-qemu-image.py` against the exact manifest pin. Debian's
documented unsigned-publisher checksum policy still applies. Seconds below
are end to end, including verification. Order alternated in each series.

| Series and pair | Publisher | Private R2 |
| --- | ---: | ---: |
| 1 / 1 | timeout | fetch failure |
| 1 / 2 | 6.832 | 16.568 |
| 1 / 3 | 7.397 | 7.365 |
| 2 / 1 | 7.542 | 8.834 |
| 2 / 2 | 6.636 | 6.361 |
| 2 / 3 | timeout | fetch failure |
| Median of four successes | 7.115 | 8.100 |
| Range of four successes | 6.636–7.542 | 6.361–16.568 |

Both paths verified four of six attempts. The mirror demonstrated correct byte
delivery and no speed or reliability win on this host. It remains a canary.
A hosted comparison should use one private digest-keyed S3 object and short
GET-only authorization, repeat against the same publisher pin and runner
region, and report timeout/fallback separately. A CDN test is a separate
comparison. Never admit or boot a partial, stale, or corrupt image.
[Presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/)
· [Cacheable size limits](https://developers.cloudflare.com/cache/concepts/default-cache-behavior/#cacheable-size-limits)

## Experiments to run next

1. **Reuse release binaries.** Trial one Linux platform. Bind the source,
   workflow signer, producer run and attempt, native dependency and OCI
   identities, toolchain, features, target, profile, and binary hashes. Only
   promote successful trusted main builds. Keep packaged ABI smoke, SBOMs,
   signing, R2 readback and the latest marker.
   [GitHub attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
   · [SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements)
2. **Remove repeat setup and compilation.** Measure a pinned helper and QEMU
   controller image against the current setup. Preserve libslirp validation,
   package signatures, dependency inventory and explicit rolling-mirror
   checks. Then compare one heavy nextest suite using a same-ABI archive and
   independent partitions. Reconcile the exact test ID union and retain serial
   libtest and shared-state constraints. Separate trusted cache publishing from
   read-only PR consumption. Profile final links independently of cache hits.
   [Nextest archives](https://nexte.st/docs/ci-features/archiving/)
   · [Nextest partitions](https://nexte.st/docs/ci-features/partitioning/)
   · [sccache](https://github.com/mozilla/sccache)
3. **Canary one Linux helper or prebuilt runtime job on Cloudflare.** Use a
   reusable pinned amd64 image, exact-source private R2 inputs, one active
   instance and a fixed deadline. Return a bound execution receipt. Verify
   privileges, cancellation, timeout and teardown under the replacement
   scheduling policy. OMG's prior runtime body took 32 seconds, but the full
   Cloudflare release compile exceeded 20 minutes. Measure the entire critical
   path. Workers Builds fits Worker deploys with the documented 20-minute cap.
   [Prior pilot](plain-cloudflare-ci.md)
   · [Containers limits](https://developers.cloudflare.com/containers/platform/limits/)
   · [Scheduling policy](https://developers.cloudflare.com/containers/configuration/scheduling-policy/)
   · [Workers Builds limits](https://developers.cloudflare.com/workers/ci-cd/builds/limits-and-pricing/)
4. **Shard the guest work before replacing the VMM.** In #1058 Fedora's
   inventory rows totalled 281 seconds. The genuine Rust install took 113
   seconds. Shadow two guests booted from one sealed read-only base with
   independent writable overlays, identities and budgets. Split only isolated
   rows and prove each expected case ran once. Keep live install and native
   build/execute probes, reboot, systemd, privilege, package mutation, and
   reset/fault evidence. Controller and guest resource caps need their own
   capacity experiment. [Hosted evidence](https://github.com/omg-cli/omg/actions/runs/44313803542#artifacts)
5. **Shadow alternate VM capacity.** Cloud Hypervisor is the closest
   candidate for a firmware-boot trial against the existing publisher image
   and all current guest oracles. Firecracker and Kata fit isolated helper
   workloads. Fresh boot IDs, guest device behavior and transaction reset
   need direct parity evidence before retiring QEMU lanes. Use supported KVM
   hardware and an ephemeral, isolated runner with restricted access if
   hosted capacity is the bottleneck. Keep real ARM and macOS checks.
   [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor)
   · [Firecracker](https://firecracker-microvm.github.io/)
   · [GitHub ephemeral runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners)
6. **Keep the Windows inner loop disposable.** Use native WHPX fresh overlays
   or verified remote bundles. Keep guest writes on C: outside WSL and retain
   only necessary evidence after cleanup. [Local QEMU](../qemu-local.md)
7. **Verify exact-main delivery during bursts.** Rehearse three rapid main
   pushes under the configured GitHub queue policy. An intermediate lost
   baseline can block later exact-base coverage. Rehearse stacked PRs and
   synthetic merge provenance before enabling merge queue. Preserve GitHub's
   required check names and signer identity.
   [GitHub concurrency](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#concurrency)
   · [Merge queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)

Cloudflare explicitly lists R2 within the shared startup award. Measure actual
Containers billing and credit application before expanding compute. Standard
GitHub runners for public repositories have no minute charge, so judge
alternative capacity on whole-check latency and reliability.
[Startup terms](https://www.cloudflare.com/startups/)
· [R2 pricing](https://developers.cloudflare.com/r2/pricing/)
· [Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/)
· [GitHub billing](https://docs.github.com/en/actions/concepts/billing-and-usage)

# CI latency and Cloudflare

This change lets native builds start after change classification while the full
workflow checks run independently. CI Success requires both jobs. It does not
remove tests, relax result handling, move QEMU to another runner, or change a
native release recipe.

## Measured baseline

[CI run 37626327378, attempt 2](https://github.com/omg-cli/omg/actions/runs/37626327378/attempts/2)
at `828964673c14a5b1e45c92ab48d190462389713f` measured:

| Job or step | Duration |
| --- | ---: |
| Quick Gate | 399 seconds |
| Portable Rust | 1,002 seconds |
| Ubuntu 26.04 environment setup | 476 seconds |
| Ubuntu 26.04 nextest installation step | 149 seconds |
| QEMU guest lanes | 426–687 seconds |

The nextest step mostly updated APT indexes and installed its missing `jq`
dependency. The binary download and verification took about one second. The
Ubuntu 26.04 setup now includes `jq` in its existing package transaction, avoiding
the second package-index update. This does not change its OS, APT ABI, Rust
toolchain, validation binary, daemon-catalogue proof, or test selection.

The six-minute gate was a dependency of every platform job. GitHub's
[`needs` semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idneeds)
explain that serialization. The new `workflow-checks` job retains the original
checks and classification conditions, and the final gate rejects failure,
cancellation, skipped, and missing results. Actual end-to-end improvement must
be measured on the candidate commit; queueing, package mirrors, cold caches,
and the longest native/QEMU lane still affect elapsed time.

## Optional portable compiler cache

The portable job supports a private R2-backed sccache cache. It is disabled unless
repository variable `OMG_R2_CACHE_ENABLED` is exactly `true`. It runs only on
`push` or `workflow_dispatch` for `refs/heads/main`; `skip-cache` disables it.
PRs and merge groups receive no R2 credentials through these steps and retain
the existing cache/build behavior. This initial integration is not a PR cache
speedup claim.

Provision a dedicated `omg-ci-compiler-cache` bucket with a 30-day object expiry
and a one-day incomplete-multipart expiry. Store only disposable compiler cache
entries there, never QEMU evidence, release provenance, or published archives.
Set `OMG_R2_CACHE_ACCOUNT_ID` to the account ID, and add bucket-scoped S3
credentials as repository secrets:

- `OMG_R2_CACHE_ACCESS_KEY_ID`
- `OMG_R2_CACHE_SECRET_ACCESS_KEY`

Use R2 Object Read & Write permissions for this bucket only. See
[R2 authentication and token scope](https://developers.cloudflare.com/r2/api/tokens/).
Keep activation disabled until the credentials are installed. Once enabled,
missing credentials or a failed cache probe fail the job rather than claiming
a working cache. The probe compiles a unique Rust library, requires a successful
cache write, deletes the output, and requires a Rust cache hit that restores the
identical library. Starting the server alone is insufficient: sccache can
downgrade an inaccessible writable backend to read-only mode.
Set the variable back to `false` to restore the original path.
No shared cache write credential is exposed to PR code.

The integration pins sccache 0.18.0 and uses HTTPS, region `auto`, and the
`portable-v1/` prefix, following
[sccache's R2 configuration](https://github.com/mozilla/sccache/blob/v0.18.0/docs/S3.md).
Credentials exist only in the setup step and its cache-server process, not in
GitHub environment/output files or test receipts. Cache statistics are printed
at job completion. Compare cold and warm **successful** main runs, including
cache hits/misses and test counts, before expanding use. The
[Rust cache limitations](https://github.com/mozilla/sccache/blob/v0.18.0/docs/Rust.md)
mean Clippy/check-only compilation and final linking must not be assumed to
benefit. Tests always execute; this cache does not reuse test outcomes.

## QEMU preservation and Cloudflare boundaries

QEMU continues to use the existing KVM runners, pinned base images, fresh
disposable guests, inventory, lifecycle operations, negative assertions,
architecture selections, evidence export, and final release admission.
`scripts/native-build-artifact.py` deliberately rejects `RUSTC_WRAPPER` and other
foreign build overrides. Native producers are outside the new cache's scope.
Neither compiler-cache contents nor a successful portable job authorize native
artifact reuse.

Cloudflare's [Containers FAQ](https://developers.cloudflare.com/containers/faq/)
documents Docker-in-Docker with restricted networking, but does not establish
the `/dev/kvm` and host/guest capabilities required by this harness. Containers
also have [standard per-instance limits](https://developers.cloudflare.com/containers/platform/limits/).
Docker support alone is not evidence that the QEMU matrix can move there.

R2 could serve pinned base-image bytes without replacing guest execution. Any
future mirror must pass the existing independent digest and provenance checks,
copy into a fresh private guest workspace, and retain upstream fallback for a
cache miss. Never cache a mutated guest disk or use a cached receipt as proof
of a new execution. This change does not enable that mirror.

Prepared native build images and per-distro QEMU scheduling require a separate
change to the producer/consumer recipe and dependency contracts. The existing
matrix barrier remains intact here; simply removing it would reintroduce races
with native artifact producers.

[Cloudflare's startup program](https://www.cloudflare.com/startups/) explicitly
covers R2. Containers billing eligibility and KVM capability have not been
verified for this account, so no Containers migration is activated by this work.

# Cloudflare CI improvements for the CodeLoud owner

This handoff describes improvements made in OMG after adapting the CodeLoud pipeline. The review is dated October 20, 2026. CodeLoud was inspected read-only and remains unchanged at the last observed owner revision `ed8cd06cda8cf65118f03718e50442f6d4cdda5a`. Review the current owner checkout before applying anything.

The OMG implementation is in [PR 974](https://github.com/omg-cli/omg/pull/974). It preserves CodeLoud's Workers/Workflow/Sandbox/OpenCode architecture and separate trusted publisher. Human approval, merge and release remain required. Do not copy OMG resource names, credentials, image pins or Rust acceptance settings into CodeLoud.

## Improvements to transfer

### Retry-safe preservation of streamed logs

Commit `e41619c2deffc007e5b1a009a59f565911d6089b` changes `services/cloud-ci/src/pipeline.ts` and adds `test/pipeline-preservation-retry.test.mjs`.

The previous preservation callback consumed stdout/stderr streams inside a retrying `step.do`. If an R2 write then failed, the next callback attempt reread an already-disturbed stream. The baseline failed with the actual Workerd error. The fix consumes each stream once before entering the retrying write step, retaining reusable strings for callback retries.

The regression exercises actual Workerd and R2 stream bodies with an explicit callback-retry fixture. It checks transient stdout, stderr and report-write failures, inline output, exact persisted bytes and SHA-256 values, and permanent failure after three attempts. It does not claim to exercise the hosted Workflow scheduler or a real Sandbox. Existing report schemas, check inventories and hash admission remain intact. Whole-log memory buffering is an existing limit that this fix does not solve.

For CodeLoud, apply the same stream-consumption ordering at its own preservation callback. Adapt the fixture's repository, check names and report names to CodeLoud's actual plan. Keep the old assertion-failing control and raw-byte/hash assertions. [Workflow replay and idempotency rules](https://developers.cloudflare.com/workflows/build/rules-of-workflows/), [step limits and external evidence storage](https://developers.cloudflare.com/workflows/reference/limits/).

### Publisher identity for a dedicated GitHub App

Commit `05e63afb6f2d332082c2e25f8f74e84b1a9a4eaa` updates `scripts/ai-review-publication.mjs`, its regression tests and the trusted publisher job.

Deduplication previously recognized only `github-actions[bot]`. A dedicated App would not recognize its own earlier issue or PR. One predicate now binds the expected login and numeric GitHub actor ID for stored records and actual write-response authors. The default Actions bot still works. A different publisher requires both trusted configuration values; partial or invalid configuration rejects before writes. Model proposals cannot select the identity. Closed-record, stale-head, exact tree and proof checks remain required.

In OMG the variables are `OMG_CI_PUBLISHER_LOGIN` and `OMG_CI_PUBLISHER_ID`. CodeLoud should use its own trusted variable names. No App credential was provisioned by this change. With a wrongly configured token, the first issue may exist before its mismatched response author is detected; the code stops before subsequent writes but cannot undo that issue. There is no claim of pre-write token-actor introspection.

Use a repository-restricted App with Contents write, Issues write and Pull requests write for the current publisher. Mint a fresh installation token only in the trusted publisher job. Do not store a short-lived installation token as a permanent secret or give it to OpenCode. The current official action uses the App client ID. [GitHub App authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow), [minimum permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

### Continuous checks for the pipeline's own source

The separate `.github/workflows/ci-orchestration.yml` runs on pull requests, main pushes and merge groups. It uses read-only repository permissions, pinned checkout/Node setup and a SHA-verified Bun binary. It installs the four frozen dependency sets without lifecycle scripts, runs the four suites, checks all seven service TypeScript contexts and dry-builds the three Workers. It receives no Cloudflare service tokens or deployment credentials and performs no model calls or deployment.

This fills the bootstrap gap left by manual-only cloud activation workflows. CodeLoud already has related coverage in `desktop-tests.yml`; compare its actual coverage before adding another duplicate workflow. Preserve its existing browser/native checks. [GitHub event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

### Preserve upstream skills without classifying examples as authored debt

OMG's generated skill bundle and manifest now live in its existing `vendor/ci-coder-skills` boundary. Their bytes and hashes are unchanged; the authored Workerd adapter and validation code remain maintained service source. Runtime imports, tests, generator and documentation use the new location. The original debt baseline and checker remain unchanged.

CodeLoud should adopt this only if its own maintained-versus-vendored policy has the same issue. Do not normalize or delete upstream examples merely to satisfy a source scanner. OMG also added one exact historical scanner fingerprint for a source-provenance hash independently reproduced from CodeLoud's immutable Git blob. That exception is specific to OMG's history and must not be copied as a general scanner exclusion.

## Research-backed next improvements

These remain recommendations, not completed capabilities.

| Priority | Confirmed current limit | Smallest next improvement and required proof |
| --- | --- | --- |
| 1 | Pending verification progresses when the authenticated courier calls status. Durable data alone does not schedule the next application poll. | Reuse the installed Lifecycle job queue to wake the existing bounded status function. Prove courier disappearance, actual DO eviction, one continuation and no duplicate remote run. Do not overwrite Lifecycle's physical alarm. [OpenCode durability](https://developers.cloudflare.com/agents/harnesses/opencode/). |
| 2 | Review workflows are manual-only. Result records do not provide a durable backlog cursor or lease. | Add one repository-scoped coordinator using existing DO storage, atomic task claims, lease generations and persisted dispatch intents. Keep held work visible. Prove duplicate ingress, lost acknowledgements, crash recovery and fair progress. [DO SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), [alarm delivery](https://developers.cloudflare.com/durable-objects/api/alarms/). |
| 3 | A successful new-regression repair does not prove an existing weak test detects the intended failure. The current adapter holds strengthening/dependency modes. | Add the existing four-state recipe and explicit dependency receipts before importing those backlog categories. Trial [cargo-mutants](https://mutants.rs/) as a source of bounded candidate faults, retaining missed, unviable and timeout states separately. A surviving mutant is a lead, not a proven bug. |
| 4 | The cloud dependency snapshot fetches dependencies; it does not establish reusable compiled Rust targets across repair operations. | Measure cold/warm compile, restore and execution time. For the same exact source/toolchain/feature/ABI, trial nextest build archives and partitioned runs. Preserve source and executable hashes. A changed mutant or repaired source requires its own build identity. [Nextest archives](https://nexte.st/docs/ci-features/archiving/), [upstream partition example](https://github.com/nextest-rs/reuse-build-partition-example/blob/main/.github/workflows/ci.yml). |
| 5 | More concurrent workflows can compete for the same two-container application. Diagnostic sequence/history currently restarts in each DO lifetime. | Measure capacity waits and add shared admission only if demonstrated contention requires it. Persist a bounded diagnostic epoch/history and expose pending/held/deadline states. Keep tokens and candidate payloads out of diagnostics. [Container limits](https://developers.cloudflare.com/containers/platform/limits/), [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/). |

Nextest already supports test groups for shared-state tests. Use that existing mechanism before increasing global concurrency. Do not remove the Fedora package-state group or retry first-attempt regressions. [Test groups](https://nexte.st/docs/configuration/test-groups/).

`sccache` is another possible compiler optimization, but requires measurement and careful cache admission. Its Rust backend has documented limitations, including incremental compilation. Direct R2 configuration normally needs credentials, so do not hand cache credentials to candidate processes. Prefer the existing trusted storage boundary before introducing another cache service. [Rust caveats](https://github.com/mozilla/sccache/blob/main/docs/Rust.md), [R2 backend configuration](https://github.com/mozilla/sccache/blob/main/docs/S3.md#R2).

## Reference acceptance and billing

CodeLoud run `39504470869`, attempt 1 at f437, ended in `chromium-browser-channels` exit 1. Internal records show dependencies, formatting, Linux symlinks, builds, portable units, static checks, subscription service and corresponding preservation steps succeeded. The portable-unit XML was independently retrieved with HTTP 200, 443,741 bytes and SHA-256 `e667fb60f9d8b2d29ebac6661f32fac181068070bd1ebbdc26215309ce8261e2`. It contains 1,906 cases, 20 exclusions, zero failures/errors and 1,886 executed cases. This supports the earlier large-log correction; it does not turn the failed complete run or later lifecycle patch into hosted acceptance.

The full per-service Tier 3 review is [Startup credit coverage](cloudflare-startup-credit-coverage.md). It separates explicitly documented eligible services from general-policy support and actual invoice deductions. No 100-percent all-SKU guarantee is supported for Containers, Artifacts, registry fees and the fixed subscription from the evidence currently available.

## Gates that must remain open

- One full hosted OMG deterministic run and genuine OpenCode-generated repair/export/PR are still required. Component fixtures do not earn that credit.
- Native/QEMU, coverage, lint, release checks and human approval remain required. No source forecast or old-head receipt substitutes for them.
- Default-branch activation, dedicated App credential provisioning and actual App-owned replay remain separate operator steps.
- Existing-PR branch repair, four-state strengthening, dependency repair and durable backlog ingestion are not silently enabled by this handoff.
- No CodeLoud deployment, resource, credential, issue or PR was modified by this work.

## Improvement validation

The five implementation commits are `e41619c2deffc007e5b1a009a59f565911d6089b` (stream retry), `05e63afb6f2d332082c2e25f8f74e84b1a9a4eaa` (publisher actor), `89bc5d6a09b991ca66c048f5c7abd0881859fa9e` (byte-exact vendor relocation and one verified historical provenance finding), `d0697bfed6b0aebc14c6d7832cd19c5b336b917b` (secret-free PR checks), and `3e3759f8bec1f3c8efec4cf4481362a5b156b9af` (bounded Workerd fixture).

There are now **238 distinct local pipeline tests**: verifier 80, inspector 26, coder 29, courier/publisher 103. Repeated runs and the fixture's five modes are not added as extra tests. All seven strict TypeScript contexts passed. The verifier's 80 tests passed again in the root's final run with 413 assertions.

A root verification run exposed the new Workerd fixture's default five-second deadline under concurrent type checking. It timed out at 5,001 ms. The fixture now has an explicit 30-second test deadline, 20-second operation deadline with Miniflare disposal, and a 25-second child-process fallback. Under seven concurrent type-check processes the fixture took 8.45 seconds and passed, demonstrating why the default was insufficient. A forced operation-deadline control exercised cleanup. Product-command timeouts, evidence assertions and permanent-failure retry counts were unchanged. [Bun test deadlines](https://bun.sh/docs/test), [subprocess controls](https://bun.sh/docs/runtime/child-process).

The original failed PR merge's exact ancestry was replayed for the debt ratchet with the relocation overlaid. It passed against the original main base without changing the baseline. The original six-commit redacted Gitleaks scan also passed after its exact provenance fingerprint exception. These are local reproductions; the fresh GitHub checks for the final PR head must still reach terminal results.

The updated OMG verifier Worker was deployed as version `1e4d4ec6-2ed3-4413-9197-9dc9eda2c151`. Wrangler reported no changes to the existing container application or its image. The image remains manifest `sha256:7d7c8bc89570da1e1234a3596758db6d3d046ba969eccc56ea1e9937166f47a3`, from runner source `2d4a40a4590111fd6b7c9c94bd0ff80479959a2a`. Worker code revision and embedded runner revision are separate identities. A deployed Worker and passing health response do not establish a completed hosted workload.

The coder was redeployed from the same reviewed source after the byte-exact skill relocation as version `4d8deeb2-e78f-4958-869b-49c0632dc473`. The inspector remains version `f88ad40b-a903-4432-80d4-83337987731c`. Redeployment did not provision a new DO or reuse CodeLoud credentials. Post-deployment probes verify authentication and request rejection, not actual model inference.

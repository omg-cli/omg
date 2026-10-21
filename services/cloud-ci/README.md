# OMG Cloudflare portable CI

This Worker ports CodeLoud's `@cloudflare/ci` 0.2.0 pipeline with its reviewed Bun patches, Sandbox 0.12.12 runtime and an OMG Rust image. Trusted image commands run against an exact commit mirrored into the `omg-ci/omg` Artifacts repository. GitHub credentials stay in the trusted courier/publisher, outside candidate execution and model tools.

See the existing [adaptation research](../../docs/operations/cloudflare-ci-adaptation-research.md), [activation and open questions](../../docs/operations/cloudflare-ci-research-open-questions.md), and [implementation plan](../../docs/plans/2026-10-20-opencode-pipeline.md). The pinned CodeLoud handoff informed this port; it is not copied into this repository.

## Deployment and acceptance

As of 2026-10-20, the owner has deployed `omg-cloud-ci`, `omg-ci-coder` and `omg-ci-inspector`. Deployment alone does not establish passing portable checks, a successful OpenCode repair, or a verified fix PR. Complete hosted fix-to-PR acceptance remains pending. Existing OMG native, coverage, Docker, QEMU and release gates remain required; this portable receipt does not replace them.

The actual image digest and verifier revision are pinned in `wrangler.jsonc` and must agree with the coder and trusted courier policy. A copied CodeLoud digest or earlier successful receipt is not evidence for a new OMG image or source revision.

## Authenticated API and source identity

`POST /runs` accepts `{repository:"omg-cli/omg",sha:"<40 lowercase hex>",ref:"refs/heads/main",runId:"123",attempt:"1"}`. Only `main` is admitted. Mirror the exact Git object before sending the request. Owner application routes require `Authorization: Bearer <CI_API_TOKEN>`; the schema in `src/contract.ts` is authoritative. The Sentry webhook uses its own signature authentication described below.

The response identifies the run and its status/receipt routes. Poll `GET /runs/<id>` for Workflow status. Admit `GET /runs/<id>/receipt` only after checking the complete source identity, trusted image and plan hashes, required checks, and every referenced log/report hash. Missing receipts, incomplete Workflows, failed checks and identity conflicts are not success. Failed attempts remain evidence; do not reuse their identities to manufacture a new passing result.

## Seven-check Rust plan

`runner/plan.mjs` defines the complete required list for `refs/heads/main`:

| Check | Actual trusted recipe |
| --- | --- |
| `frozen-dependencies` | `cargo fetch --locked`, frozen Bun installation and dependency installation for all three required services |
| `source-format` | `cargo fmt --all -- --check`; a failure blocks dependent checks |
| `rust-portable-tests` | `scripts/run-native-contracts.py` under `pgp,license` and `debian-pure`, with platform explicitly recorded as portable |
| `script-contracts` | Shell syntax, Python script unit discovery and the three explicit Python test files in `runner/run.mjs` |
| `cloud-ci-service` | Required service source present; its `check`, `build` dry-run and `test` scripts |
| `ci-coder-service` | Required coding service source present; its `check`, `build` dry-run and `test` scripts |
| `ci-inspector-service` | Required inspector source present; its `check`, `build` dry-run and `test` scripts |

The portable Rust reports are `rust-pgp-license-junit.xml` and `rust-debian-pure-junit.xml`. This is not CodeLoud's renderer/browser/channel or Windows plan. The toolchain includes Rust 1.95.0 and pinned Bun/Node versions; `runner/plan.mjs` is the source of truth.

Verification requests add the fixed `regression-red-green` recipe. It requires one named new Rust regression to fail with an observed assertion on the original source, then pass after the validated repair, with the proposal applied to all required portable runners. Compiler, setup, missing-test and timeout failures are not behavioral RED. Receipts bind both raw regression reports to their summary hashes; coder and publisher fetch/hash those objects before admission. Dependency changes require their own receipts.

## Existing-test verification

The separate `testAudit` request is mutually exclusive with repair `verification`. It binds the exact original Git source and selects one existing root integration test or qualified `omg_lib` test. The [audit contract](src/test-audit-contract.ts) defines two purposes:

- `existing-test-sensitivity` executes only original/intact GREEN and original/fault intended assertion 101. It records sensitivity to the selected fault, with no changed paths or publication authority.
- `existing-test-strengthening` requires old/intact GREEN, old/fault GREEN, stronger/fault intended assertion 101 and stronger/intact GREEN. It preserves all original test bytes and adds one assertion inside the selected function.

The controlled fault remains private and is restored. Normal portable checks receive intact production source and, for strengthening, only the stronger test. Receipts and raw reports use a distinct `-ta-` run identity. Consumers refetch the named reports and validate their actual compiler, catalog, execution and digest joins. A historical name or selected source file earns no current execution credit. Unsupported or native-only cases remain held. See [the queue and interpretation rules](../../docs/operations/cloudflare-autonomous-repair.md#existing-test-audit).

Audit-only source files allow up to 256 KiB of UTF-8 bytes each, with a 1 MiB request envelope. Full bytes cross the trusted process boundary in at most 88 base64 chunks of 16,000 characters. Normal repair collection remains limited to 24,000-byte sources and 64 KiB CI requests. The coder's audit state cap is 1.5 MiB; private review records have a separate 2 MiB cap. Oversized input fails admission rather than being truncated.

## Execution and storage boundaries

Candidate commands run as UID/GID 10001 with a scrubbed environment, protected tracked source and explicit writable build/cache directories (`runner/portable-process.mjs`). This boundary does not disable network access. JUnit and exit codes are test observations, not independent proof that an arbitrary generated assertion describes a real product defect. Native/QEMU lifecycle and platform acceptance remain separate.

For selected Rust verification, the root controller freezes compiled artifacts and dependency inputs after Cargo completes and before both test listing and execution. It verifies their filesystem identities after each invocation. Scratch under the test's HOME/tmp remains writable. The existing preparation step reopens build caches for the next compilation. Docker build smokes exercise the Linux UID boundary and the near-limit environment transport; they do not execute or certify retained OMG tests.

Only the dependency phase is cached. Its key includes the image, trusted plan, source ref, command and relevant manifest/lockfile inputs. Before uncached checks, the trusted runner removes restored source absent from the exact commit while preserving explicit dependency directories.

`CiSandbox` supports native R2 transfers with bucket-scoped signing credentials confined to the Worker, and private binding/RPC transfer as a fallback. Candidate runners do not receive Worker, Cloudflare or GitHub credentials. The engine's optional deployment token is not required. Object retention depends on deployed R2 lifecycle configuration; this source alone does not prove particular retention periods.

`POST /source-token` issues a five-minute write credential scoped to the configured OMG Artifacts repository, with no repository/scope override. `POST /review-records/<runId>-<attempt>` stores one bounded private result record; identical retries succeed and conflicting retries fail. These result records do not establish a complete audit-backlog cursor or completed-method inventory.

## Local checks and operational changes

From this directory, run `bun install --frozen-lockfile --ignore-scripts`, `bun test`, `bun run check` and `bun run build`. Build is a Wrangler dry-run, not deployment. Image rebuilding requires the reviewed Docker/Sandbox toolchain. Resource creation, credentials, image rollout and hosted acceptance remain owner operations.

A verification receipt alone does not authorize approval, merge, release or product deployment. The separate trusted publisher creates a regular fix PR only after exact-source and independent proof admission. The [independent approval workflow](../../docs/operations/cloudflare-autonomous-repair.md#publication-and-independent-approval) requires a fresh patch verdict and successful native, coverage and QEMU evidence for the exact PR head. It does not merge or release the PR.

## Sentry runtime evidence

The optional `POST /sentry/events` endpoint accepts Sentry internal-integration issue alerts. Configure the `SENTRY_WEBHOOK_SECRET` Worker secret and explicit `SENTRY_ORG_SLUG`, `SENTRY_PROJECT_SLUG`, `SENTRY_PROJECT_ID` and `SENTRY_ENVIRONMENT` allowlist variables before enabling the alert action. Missing configuration fails closed. The endpoint verifies HMAC-SHA256 over the original body bytes and caps input at 256 KiB. It never fetches payload URLs. [Sentry signature documentation](https://docs.sentry.io/integrations/integration-platform/webhooks/).

Private immutable evidence contains event/issue identifiers, the signed-body digest, optional release/source attribution, safe error type identifiers and up to 12 Rust frame candidates. Exception stacks, native thread stacks and Rust tracing locations are supported. Absolute frames require explicit OMG crate ownership and in-app marking; the consumer must still resolve their actual immutable Git blobs. Raw messages, users, requests, variables, absolute paths and breadcrumbs are discarded. An event without usable Rust frames remains retained with an explicit hold reason. Unknown or historical source attribution remains separate from the main commit selected for review.

The webhook response means `queued`, not reviewed or repaired. The existing authenticated coordinator reads `GET /sentry/events?limit=1&cursor=<opaque>` as `{events, cursor}`. Limits are 1 to 50, with 25 by default. Only the ephemeral pending index is enumerated, so acknowledged history cannot starve new events. `GET /sentry/events/<projectId>/<eventId>` retrieves the immutable envelope even after acknowledgement.

The scheduled consumer uses authenticated `POST /sentry/poll` with `{}` to advance a durable round-robin cursor and receive one pending event. The server persists the cursor with an R2 conditional write before returning, then wraps at the end of the index. A stale active review therefore cannot block every later event. A consumer crash after polling leaves the event pending for a later round; a cursor storage failure returns unavailable rather than an empty queue. The GET listing remains read-only.

Before inference, authenticated `POST /sentry/events/<projectId>/<eventId>/reserve` binds the pending event to `{runId, attempt, sha, controllerRevision}` using its real R2 entity tag and a conditional write. The body contains `bodySha256`, `activeReview` and `expectedActiveReview`, with `null` for an initial claim. An identical retry succeeds; a competing claim fails. Pending listings expose the optional active review reference separately from the immutable event. A durable record for the old review blocks replacement, including an empty result record. The coordinator must resume that result or hold it, rather than generating a new no-findings result that could discard an unpublished verified fix.

After durably storing its review result, the coordinator sends authenticated `POST /sentry/events/<projectId>/<eventId>/ack` with `{bodySha256, reviewRunId, attempt}`. Admission requires the existing private review record to reference that exact event digest. Identical retries succeed, conflicting acknowledgements fail, and only the pending pointer is deleted. Evidence and acknowledgement remain immutable. A crash before pending insertion or after acknowledgement persistence recovers on retry. Source review, a designated regression RED/GREEN and the existing independent verifier/publisher gates still decide whether a regular fix PR can be created.

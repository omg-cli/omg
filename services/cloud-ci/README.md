# OMG Cloudflare portable CI

This Worker ports CodeLoud's `@cloudflare/ci` 0.2.0 pipeline with its reviewed Bun patches, Sandbox 0.12.12 runtime and an OMG Rust image. Trusted image commands run against an exact commit mirrored into the `omg-ci/omg` Artifacts repository. GitHub credentials stay in the trusted courier/publisher, outside candidate execution and model tools.

See the existing [adaptation research](../../docs/operations/cloudflare-ci-adaptation-research.md), [activation and open questions](../../docs/operations/cloudflare-ci-research-open-questions.md), and [implementation plan](../../docs/plans/2026-10-20-opencode-pipeline.md). The pinned CodeLoud handoff informed this port; it is not copied into this repository.

## Deployment and acceptance

As of 2026-10-20, the owner has deployed `omg-cloud-ci`, `omg-ci-coder` and `omg-ci-inspector`. Deployment alone does not establish passing portable checks, a successful OpenCode repair, or a verified fix PR. Complete hosted fix-to-PR acceptance remains pending. Existing OMG native, coverage, Docker, QEMU and release gates remain required; this portable receipt does not replace them.

The actual image digest and verifier revision are pinned in `wrangler.jsonc` and must agree with the coder and trusted courier policy. A copied CodeLoud digest or earlier successful receipt is not evidence for a new OMG image or source revision.

## Authenticated API and source identity

`POST /runs` accepts `{repository:"omg-cli/omg",sha:"<40 lowercase hex>",ref:"refs/heads/main",runId:"123",attempt:"1"}`. Only `main` is admitted. Mirror the exact Git object before sending the request. Application routes require `Authorization: Bearer <CI_API_TOKEN>`; the schema in `src/contract.ts` is authoritative.

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

Verification requests add the fixed `regression-red-green` recipe. It requires one named new Rust regression to fail with an observed assertion on the original source, then pass after the validated repair, with the proposal applied to all required portable runners. Compiler, setup, missing-test and timeout failures are not behavioral RED. Receipts bind both raw regression reports to their summary hashes; coder and publisher fetch/hash those objects before admission. Existing-test strengthening remains held until its four-state recipe is integrated, and dependency changes require their own receipts.

## Execution and storage boundaries

Candidate commands run as UID/GID 10001 with a scrubbed environment, protected tracked source and explicit writable build/cache directories (`runner/portable-process.mjs`). This boundary does not disable network access. JUnit and exit codes are test observations, not independent proof that an arbitrary generated assertion describes a real product defect. Native/QEMU lifecycle and platform acceptance remain separate.

Only the dependency phase is cached. Its key includes the image, trusted plan, source ref, command and relevant manifest/lockfile inputs. Before uncached checks, the trusted runner removes restored source absent from the exact commit while preserving explicit dependency directories.

`CiSandbox` supports native R2 transfers with bucket-scoped signing credentials confined to the Worker, and private binding/RPC transfer as a fallback. Candidate runners do not receive Worker, Cloudflare or GitHub credentials. The engine's optional deployment token is not required. Object retention depends on deployed R2 lifecycle configuration; this source alone does not prove particular retention periods.

`POST /source-token` issues a five-minute write credential scoped to the configured OMG Artifacts repository, with no repository/scope override. `POST /review-records/<runId>-<attempt>` stores one bounded private result record; identical retries succeed and conflicting retries fail. These result records do not establish a complete audit-backlog cursor or completed-method inventory.

## Local checks and operational changes

From this directory, run `bun install --frozen-lockfile --ignore-scripts`, `bun test`, `bun run check` and `bun run build`. Build is a Wrangler dry-run, not deployment. Image rebuilding requires the reviewed Docker/Sandbox toolchain. Resource creation, credentials, image rollout and hosted acceptance remain owner operations.

No automatic approval, merge, release or product deployment is authorized by a verification receipt. The separate trusted publisher may create a regular fix PR for human review only after exact-source and independent proof admission.

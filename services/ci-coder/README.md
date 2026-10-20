# OMG coding Worker

This private Worker runs OpenCode in a SQLite Durable Object with direct Workers AI inference. Its only coding tools read an immutable Git snapshot, propose a bounded repair, and request independent Cloudflare CI execution. GitHub credentials stay in the separate trusted publisher.

Potato Mode, Ponytail, Rust best practices and TDD are mandatory. The bundled original skill files retain provenance, hashes and licenses. The runtime validates the bundle before creating a session and injects the required instructions into the SDK's context, compaction and generation hooks. Every coding tool requires actual delivery to its session. A model saying it used the skills is insufficient.

Operations bind the repository, exact commit, branch, run, attempt, source snapshot and hypothesis. Retries reuse the same operation identity. A different skills bundle, image or verifier cannot silently resume an existing operation.

## Verify locally

Run from the repository root with Bun.

```sh
bun install --cwd services/ci-coder --frozen-lockfile --ignore-scripts
bun run --cwd services/ci-coder check
bun run --cwd services/ci-coder test
bun run --cwd services/ci-coder build
```

`bun services/ci-coder/build-skills.mjs <rust-skill-root> <tdd-skill-root>` appends the pinned Rust/TDD sources to the retained CodeLoud registry and regenerates its hashes. Review and commit the resulting manifest and bundle together.

## Deploy and probe

The Wrangler configuration binds Workers AI, the `Coder` Durable Object, and the existing `omg-cloud-ci` service. `CODER_API_TOKEN` protects the owner API. `CI_API_TOKEN` authenticates verification requests. Store both through Wrangler's secret stdin, never in source or model context. Pin `CI_IMAGE_DIGEST` and `CI_VERIFIER_REVISION` to the trusted verifier deployment.

The trusted courier reads `~/ci/omg-ci-coder.json`. It contains `endpoint`, an absolute protected `tokenFile`, and the expected `bundleSha256`. Keep equivalent protected configuration on each authorized courier. No customer key belongs in this file.

```sh
bun services/ci-coder/test/harness-runtime.mjs <exact-commit> <main> <isolated-probe-id> <attempt>
```

The probe reads actual Git objects and checks durable runtime identity, skill delivery and source reads. It does not publish a GitHub issue or PR. A successful no-findings probe proves runtime execution, not a successful repair or complete repository review.

Publication separately re-fetches the coding result, Cloudflare verifier receipt, original Git objects and hashed evidence. Only an exact verified repair can produce a regular PR. Merging, approval, deployment and releases remain human-controlled. The existing OMG native/QEMU gates remain required.

See the [adaptation research](../../docs/operations/cloudflare-ci-adaptation-research.md) and [activation questions](../../docs/operations/cloudflare-ci-research-open-questions.md) for the handoff basis and limits.

## Reuse in another repository

Keep the runner, evidence verification and publication boundaries. Replace the explicit repository and source-path policy, trusted controller revision, protected courier configuration and required check inventory as one reviewed change. Do not loosen the repository allowlist to onboard another product. Validate that product's actual intact/fault behavior before enabling writes.

## Port provenance and activation

Ported directly from `CodeLoud/codeloud-desktop` commit `f4371c4ccacbf5fe7ab6e5c776bd9151c9a6850c`. The OpenCode harness, Durable Object lifecycle, tool budgets, verification receipt admission, and separate publisher architecture are retained. The adapter admits `omg-cli/omg` on `main`, Rust production sources and designated Rust regression files. The legacy `cl-` operation prefix remains a protocol identifier shared with the copied courier/verifier, not a resource name.

The committed Wrangler configuration now contains the OMG account, image digest and verifier revision and binds `CI_SERVICE` to `omg-cloud-ci`. Those pins must match the actual trusted deployment and courier policy; CodeLoud image pins must never be used as OMG acceptance. Runtime admission rejects missing or malformed pins. OMG Worker, Durable Object and credential names are separate; no CodeLoud credential is copied.

As of 2026-10-20, the owner has deployed all three OMG Workers. Complete hosted repair-to-PR acceptance remains pending. A local test or dry-run is not hosted execution evidence. Before enabling publication, demonstrate one actual regression RED, repaired GREEN, complete receipt/object verification, and a human-reviewable PR. Existing-test improvements also require four-state evidence. Existing PR repair is permitted only through a separately admitted owner-controlled same-repository branch policy; this initial main-only adapter does not grant arbitrary branch writes.

## Verification waits and raw proof

`verify_patch` starts the idempotent remote run, stores its exact proposal/session/run/deadline, and returns pending. The existing authenticated courier polls `Coder.status`; each fresh request performs at most one remote status read. On completion, the coder independently validates the receipt and reads/hashes every required object, including both raw regression reports. The admission path caps evidence at 24 object calls (the current plan uses 18 objects plus status/receipt = 20 calls), reserving room below Cloudflare's [32 Worker-invocation limit](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/#limits). It does not hold a model tool open for 35 minutes.

The installed `agents@0.29.0` OpenCode harness accepts a distinct, deterministic follow-up operation ID in the original session using `whenBusy: "followUp"`. Its submit implementation deduplicates operation IDs; reusing the initial ID would not resume a new turn. Status reports both the initial operation and continuation identity, and reports completion only after the actual continuation result. The trusted courier checks that chain. Durable pending, terminal failure and deadline survive state reload; identical failed input is not retried. Local contract tests exercise these paths; actual hosted Lifecycle restart and repair/export acceptance remain required.

The immutable generated skill bundle and manifest live in `../../vendor/ci-coder-skills/`, within the existing vendored-source boundary. Their original byte hashes and mandatory guidance are unchanged. Authored `skills/workerd/ADAPTER.md` and the validation/runtime code remain maintained service sources; no debt baseline or scanner rule is relaxed.

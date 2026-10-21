# OMG OpenCode repair pipeline

The user chose the exact CodeLoud full Cloudflare pipeline. This supersedes the earlier proposal to replace Sandbox execution with a new GHA queue. Port frozen CodeLoud `f4371c4ccacbf5fe7ab6e5c776bd9151c9a6850c`, retaining its actual OpenCodeHarness, Cloudflare Workflows/Sandbox verification, evidence objects and trusted publisher. Adapt the verifier to Rust; retain existing OMG native/QEMU required checks.

## Ownership

- Coding Worker owner: `services/ci-coder/**`. Same Durable Object/OpenCode lifecycle, bounded source tools, versioned skill registry and verification/export boundary. Required skills: Potato, Ponytail, Rust best practices and TDD.
- Root Cloudflare owner: `services/cloud-ci/**` orchestration/configuration, copied SDK patches, independent OMG resources and activation pins.
- Rust verifier owner: Rust runner/check plans, isolated regression RED/GREEN and four-state behavior verification, fixed command policy and receipts.
- Courier/publisher owner: `services/ci-inspector/**`, `scripts/ai-review-*`, `scripts/cloud-ci-*`, GitHub workflow and publication tests. Preserve exact source/blob hashes, proposal digest, receipt/object verification, stale-head refusal and human review.

## Interfaces retained from CodeLoud

`POST /operations` accepts authenticated `{repository, sha, branch, runId, attempt, source, hypothesis?, candidateIndex?}`. Exact snapshot/hypothesis contents determine the immutable named Durable Object. The Worker tools expose only source/skill reads, one bounded proposal, independent verification and verified export. No GitHub credential reaches model tools.

`POST /runs` accepts the original `{repository, sha, ref, runId, attempt, verification}` shape. Rust adapters retain proposal/regression/verifier revision and evidence schemas. CodeLoud operation prefix `cl-` remains for compatibility; actual Worker/service/storage names are OMG-specific. No new queue/protocol engine is added.

The trusted publisher independently retrieves original Git objects, coding output, trusted verifier receipts and every digest-bound evidence object. It may file a regular fix PR. Existing-PR repairs require an explicitly admitted owner-controlled same-repository branch; arbitrary/fork branches remain refused. No automatic approval, merge, release or weakened tests.

## Verification and activation order

1. Copy frozen source and preserve source provenance. Adapt repository, Rust paths/test fixtures and independent resource names.
2. Observe narrow adapter tests RED before their production changes; run copied tests and TypeScript checks, then Wrangler dry-run.
3. Build an actual OMG Rust verifier image and pin its digest/revision. Do not substitute CodeLoud image or successful evidence.
4. Deploy separate OMG resources/secrets only through the root operator. Prove actual source reads/skill delivery, then one real RED/GREEN repair and digest-bound export/PR.
5. Require current native/QEMU and human review before merging. Four-state existing-test evidence is separate from ordinary new-regression RED/GREEN.

Batch remaining audit work through the existing bounded request/source/hypothesis shape. Preserve explicit held/deferred cases and exact method IDs. A source prediction, setup failure, timeout or model statement earns no execution credit.

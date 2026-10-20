# Cloudflare CI implementation research and open questions

Updated 2026-10-20 against the current OMG adaptation worktree and frozen CodeLoud `f4371c4ccacbf5fe7ab6e5c776bd9151c9a6850c`. This separates implemented source, operator-reported activation and actual hosted acceptance. Read alongside [adaptation research](cloudflare-ci-adaptation-research.md). Primary documents below were retrieved with Firecrawl. This document update ran no deployment, AI call, native build or capability probe.

## Ready in source versus still planned

| Area | Current implementation evidence | Remaining activation or missing behavior |
| --- | --- | --- |
| OpenCode coding | `services/ci-coder/src/harness.ts`, `request.ts`, `tools.ts`; same Durable Object/OpenCode/verification/export pattern as the handoff. Focused local tests, strict TypeScript checks and Wrangler dry-run passed; verification now resumes through a distinct OpenCode continuation in the original session. | No hosted OMG session, actual repair, exported proof or generated PR has been admitted. Local results establish adapter behavior only. |
| Required skills | `services/ci-coder/skills/manifest.json` records original package paths/hashes plus Rust 1.1.2 and TDD 6.4.2; `src/skills.ts` validates bytes and records actual session injection. | Hosted delivery and continued-session recovery still need an actual receipt. Delivery is not proof the model followed instructions. |
| Discovery trigger | `.github/workflows/ai-review.yml` has only `workflow_dispatch`, with main-only repository/ref guards. `scripts/ai-review-flow.mjs` understands push/workflow-run events, but the YAML does not subscribe to them. | Automatic failed-CI, issue/label and periodic discovery are not enabled. Choose and test explicit event subscriptions before calling this unattended discovery. |
| Existing PR repair | `services/ci-coder/src/request.ts`, cloud request admission and publisher policy are main-only. Publisher creates an `ai-fix/...` branch and regular PR (`scripts/ai-review-publication.mjs`). | No admitted owner-controlled existing-PR branch-update mode. Do not infer it from GitHub's API capability or the presence of PR-diff collection. |
| Audit backlog | `ai-review-flow.mjs:199-214` reports oversized/unreviewed paths; `review-source-evidence.mjs:156-164` enforces source/file budgets. Named DO identity prevents changing an existing operation's input. | No durable audit-catalog cursor, claim/lease, explicit held-debt ingestion or completed-method reconciliation was found in this path. Existing review records are result storage, not proof of complete backlog coverage. |
| Independent execution | Cloud CI and Rust runner sources are ported. Coder and publisher require trusted receipt/object hashes, including actual baseline/patched report retrieval. The OMG image is built/pushed with the immutable pins below. | Cloud service deployment is in progress; coder deployment is pending. Actual deployed identity, complete execution and proof export remain required. |

## Current image and hosted prerequisite status

The operator reports the final OMG image pushed and its raw registry manifest verified:

- Image digest: `sha256:7d7c8bc89570da1e1234a3596758db6d3d046ba969eccc56ea1e9937166f47a3`.
- Verifier/source revision: `2d4a40a4590111fd6b7c9c94bd0ff80479959a2a`.
- Both Cloud CI and coder configuration now contain those pins. This replaces the copied image placeholders; it does not prove the running deployment uses them. Cloud service deployment is in progress and coder deployment has not completed at this checkpoint.

CodeLoud is still an architectural reference, not a green hosted prerequisite. REST run [39504470869](https://github.com/CodeLoud/codeloud-desktop/actions/runs/39504470869), attempt 1 at frozen `f4371c4`, completed **failure**. Its actual job log reports the Workflow changed from `running` to `errored` and the courier refused a passing receipt at 22:22:36 UTC. The internal failed step/cause is not exposed by that log. The handoff's earlier successful unit-report component does not supersede the terminal failure. Independent retrieval of its claimed 443,741-byte report was unavailable with HTTP 403 in the read-only review; do not present its hash as independently verified here. The later clean owner head `ed8cd06` includes additional teardown/source-metadata changes and is distinct from the failed run.

## Trigger and unattended publication research

GitHub supports `workflow_dispatch`, `workflow_run`, `repository_dispatch`, issue events and schedules. Dispatch workflows must exist on the default branch; `workflow_run` has privilege and untrusted-code considerations; schedules can be delayed or dropped. These are supported platform mechanisms, not features activated by this port. [GitHub events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)

The smallest completion is to wire a bounded discovery event into the existing collector, retain exact repository/head/controller checks, and persist a visible outcome for work deferred by budgets. A schedule alone cannot establish reliable backlog completion. A privileged `workflow_run` publisher must execute its pinned trusted controller, never the candidate checkout. This follows the documented privilege boundary and the current checkout split. [GitHub workflow-run behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run)

The separate publisher job has contents/issues/pull-request write permissions. Actual publication requires the manual dispatch flag and either `OMG_CI_PUBLISHER_TOKEN` or explicit `OMG_CI_GITHUB_TOKEN_PR_CREATION_ENABLED=true`; otherwise it blocks. The fallback token is `${{ github.token }}`, with that limitation made explicit rather than silently assumed. GitHub documents that PRs created/updated with `GITHUB_TOKEN` start corresponding opened/synchronize/reopened workflows in an approval-required state. For unattended PR CI, GitHub recommends a GitHub App installation token or PAT. A PR existing is therefore not evidence its required native/QEMU checks ran. [Token trigger behavior](https://docs.github.com/en/actions/concepts/security/github_token)

A least-privilege OMG-installed GitHub App remains the preferred pending credential setup for unattended PR checks; no installed App or dedicated publisher token is established by the three service credentials. Its token must be supplied only to the trusted publisher. GitHub documents creating an installation token from the App ID/private key in Actions. Choose required permissions from the actual publication operations, not broad administrator access. [App authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow)

An explicit workflow dispatch is another supported trigger, but requires an existing dispatch-enabled workflow, a branch/tag ref and Actions-write permission. It does not automatically replace the existing push/PR check semantics or satisfy branch protection; exact checks and resulting SHA must be verified. No dispatch was sent. [Dispatch API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event)

The operator has installed the three separate OMG service secrets: `OMG_CI_API_TOKEN`, `OMG_CI_INSPECTOR_TOKEN` and `OMG_CI_CODER_TOKEN`. These are not GitHub publication credentials. Installed names do not prove deployed Worker secret bindings or successful authenticated execution; verify those separately without printing values.

## Preserve existing native, QEMU and release evidence

The port adds portable verification; it does not replace `.github/workflows/ci.yml:1660-1668` QEMU fan-out or its aggregate requirement at lines 1779-1782. `.github/workflows/release.yml:42-75` requires successful CI, benchmark, audit, secret, CodeQL, coverage and Docker workflows for the exact release SHA. The same release workflow builds platform packages and records archive hashes; keep those paths and existing attestation gates intact.

GitHub's artifact mechanism supports retaining and transferring job outputs, but an uploaded object alone does not prove platform behavior. The existing OMG exact-source/binary/JUnit/guest lifecycle and transaction joins remain the acceptance contract. No native/guest result from an earlier head may be reused as fresh execution. [GitHub workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts)

Cloudflare documents `standard-4` as 4 vCPU, 12 GiB RAM and 20 GB disk. Those resource limits do not establish nested hardware virtualization, `/dev/kvm`, macOS execution or native distro ABI equivalence. [Container limits](https://developers.cloudflare.com/containers/platform/limits/)

Docker-in-Docker is documented, with no iptables, ephemeral storage and no `wrangler dev` support. The reviewed page does not establish KVM/device passthrough or OMG's QEMU lifecycle requirements. KVM/nested-native capability is **unverified**, not claimed impossible; no native capability test was attempted. Keep current native/QEMU until a separately reviewed equivalent is demonstrated. [Sandbox Docker-in-Docker](https://developers.cloudflare.com/sandbox/sdk/guides/docker-in-docker/)

## Resource and credential isolation

The current names are `omg-ci-inspector`, `omg-ci-coder`, `omg-cloud-ci`, Artifacts namespace `omg-ci` and R2 bucket `omg-ci-private`. `services/ci-coder/wrangler.jsonc` binds only its own DO, Workers AI and `CI_SERVICE` to `omg-cloud-ci`. CodeLoud's `cl-` protocol prefix is retained for interoperability; it is not a shared storage/resource binding.

Cloudflare service bindings provide Worker-to-Worker calls without using a public endpoint; the target must be in the same account and deployed first. Sharing an account does not by itself share a Worker/DO/bucket. Deploy the verifier service before the coder and verify the actual binding target. [Service bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/)

`CODER_API_TOKEN`, `CI_API_TOKEN`, inspector credentials and publisher GitHub credentials have distinct trust roles. The model has no GitHub write token. Both manual workflows now use GitHub-hosted `ubuntu-24.04` courier jobs, not the unavailable `omg-ci` self-hosted runner. Each job downloads Bun 1.4.2, verifies the pinned binary SHA/revision, and creates private `~/ci/omg-{cloud-ci,ci-inspector,ci-coder}.json` files and token files from the three OMG secrets. Configuration files are mode 0600 in a mode-0700 directory and removed in an always-run cleanup step. Only the immutable controller checkout executes on the courier; the publisher is a separate job. This is implemented source, not a successful hosted run. [GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)

Cloudflare documents per-Worker secret bindings. Do not copy CodeLoud values or confuse GitHub secret installation with Cloudflare binding installation. [Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/)

The single-tool long-poll design has been replaced. `services/ci-coder/src/tools.ts` starts an idempotent verification job and returns pending; each fresh authenticated status request performs one status check. Terminal admission bounds evidence-object retrieval to 24 objects, leaving space below the documented 32-invocation request limit. A distinct SDK operation ID continues the original session with `whenBusy: followUp`; the original deduplicated operation is not resubmitted. Courier admission requires the actual completed continuation, matching session/proposal/verification IDs and a verified job. Local tests cover pending, replay/race, failed evidence and continuation identity; actual hosted request counts, restart behavior and completion remain acceptance gates. [Service-binding limits](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/#limits)

## Concrete activation checklist

1. Cloud CI and coder are now deployed with the built/pushed image and revision. Deployed settings readback confirms the separate OMG bindings; authenticated verifier health returns 200 and unauthenticated requests return 401. Full hosted execution remains unproven.
2. Verify separate OMG Worker/DO/Workflow/Artifacts/R2 resources and actual credential bindings. Preserve CodeLoud isolation.
3. Configure/verify `OMG_CI_CONTROLLER_SHA`, image/verifier/skill-bundle repository variables and the implemented hosted courier's three private service configurations. The three service secrets are installed; no self-hosted runner provisioning is required by these workflows.
4. Configure and test narrowly scoped publication authentication if unattended PR checks are required. Keep the manual publish flag, preview default and explicit GITHUB_TOKEN approval-policy blocker; preserve human approval, merge and release policy.
5. Run the deterministic OMG verifier before AI: actual source/commit identity, named regression RED on base, GREEN after repair, required portable checks, all fetched digest-bound evidence and stale-head refusal. Local fixtures and the pushed image do not satisfy this gate.
6. Run one real OpenCode operation with all four delivered skill entries; verify durable restart identity, bounded status polling, actual completed continuation, proof export and a separate publisher creating a human-reviewable PR.
7. Require that PR's exact-head native/QEMU and other mandatory checks. No automatic merge or release. Existing-test strengthening remains held until actual four-state execution is integrated; dependency changes need their own receipts. Existing-PR branch repair remains unsupported by current main-only admission.
8. Only then enable chosen automatic discovery/backlog subscriptions and prove deferred items remain visible and cannot be silently counted complete. A durable audit cursor/lease and held-debt reconciliation remain missing behaviors.

The handoff architecture is retained. The unresolved work above is activation and explicitly missing behavior; no alternative orchestration engine is proposed.

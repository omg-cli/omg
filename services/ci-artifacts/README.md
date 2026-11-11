# CI artifact transport

This Worker has two closed interfaces. It does not run code, deploy Containers,
perform AI work, list buckets or expose compiler-cache objects through HTTP.

| Route | Authority |
| --- | --- |
| `POST /v1/compiler-cache/credentials` | GitHub OIDC plus ephemeral job token; own-repository current PR merge only; temporary R2 `GetObject`/`HeadObject` under `portable-v1/` for at most 45 minutes. |
| `GET` / `HEAD /dependencies/sqlite-v1/{x86_64\|aarch64}/{recipe64}/{inventory64}/{name}` | Public curated bytes only. `name` is `latest.json` (64 KiB), `{archive64}.tar` (160 MiB) or `{archive64}.sigstore.json` (1 MiB). No range, query, listing or write endpoint. |
| `GET /health` | Nonsecret source, policy and seed recipe identity. |

The SQLite consumer independently verifies hashes, complete archive inventory,
original build revision/signatures and GitHub attestation, fresh DNF closure and
current-consumer admission. Transport success is not provenance admission.

Immutable archive/proof GETs also use the ordinary Workers Cache API. A hit
returns the same closed URL's guarded size/type/ETag/200 response without an R2
read. A miss uses one R2 reader and a client-driven cache branch through
`ctx.waitUntil`. The cache queue holds at most 4 MiB plus one in-flight source
chunk; backlog overflow clears and errors only that branch. Cache cancellation
and its 25-second deadline also release that queue, while client cancellation
stops the one R2 reader and the cache branch. The branch checks the exact byte
count without cloning or buffering the full archive. Cache failure,
rejection or invalid cached metadata falls back to the normal guarded R2 path.
HEAD, latest.json, credentials, OIDC and health never use that edge cache.
`X-OMG-Artifact-Cache: HIT|MISS|BYPASS` makes the path observable.

This cache is data-center-local, not replicated/tiered storage. Current limits
are 512 MB per object on Free/Pro/Business (above this courier's 160 MiB cap),
and `waitUntil` extends at most 30 seconds after response/disconnect. A resolved
put does not guarantee storage. Verify repeated same-object deployed GETs, exact
hostname behavior and latency/bytes before claiming a speedup; previews are not
acceptance. This adds no Cache Reserve subscription or separate paid cache SKU.
[Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/),
[Worker/cache limits](https://developers.cloudflare.com/workers/platform/limits/).

## Tools and checks

Reuse the exact dependencies in `services/ci/package.json` and its frozen lock;
this service has no new dependency or package installation tree. From the root:

```sh
bun install --cwd services/ci --frozen-lockfile --ignore-scripts
bun test services/ci-artifacts/test/worker.test.ts
bun run --cwd services/ci tsc --project ../ci-artifacts/tsconfig.json --noEmit
node --test services/ci-artifacts/test/deploy.test.mjs
python3 -B -m unittest discover -s scripts -p test_ci_r2_cache.py -v
node services/ci/node_modules/wrangler/bin/wrangler.js deploy --dry-run \
  --config services/ci-artifacts/wrangler.jsonc --outdir "$RUNNER_TEMP/artifact-worker-dry-run"
```

Register the first four checks in the existing required helper owner. Local
tests use generated RSA keys, Web Crypto HMAC and real in-memory SQLite. They
do not establish actual GitHub claims, R2 authorization or hosted performance.

## Trusted bootstrap

The manual `cloudflare-artifacts.yml` workflow runs only from OMG main in the
production environment. It installs pinned existing tools, proves direct Rust
output against a remote seed result, creates small immutable admission markers,
and deploys this separate Worker. Existing native-controller deployment is not
called or changed. No replacement parent key is created.

Required existing values are repository secrets `OMG_R2_CACHE_ACCESS_KEY_ID`
and `OMG_R2_CACHE_SECRET_ACCESS_KEY`, repository variable
`OMG_R2_CACHE_ACCOUNT_ID`, and production secrets `CLOUDFLARE_ACCOUNT_ID` and
`CLOUDFLARE_API_TOKEN`. Account IDs must agree. The script streams the existing
pair into `wrangler secret bulk` on stdin after an offline dry-run and deployment.
It suppresses child output, reads the final deployment after secret upload, and
checks source/policy/seed health and unauthenticated refusal. A token scope
failure is reported; it does not trigger credential creation.

The workflow's underlying commands are:

```sh
python3 scripts/ci-r2-cache.py --mode seed --receipt "$RUNNER_TEMP/omg-r2-seed.json"
node services/ci-artifacts/deploy.mjs
```

The seed role requires exact main workflow/job/source/run/attempt identity. The
seed command receives existing parent keys as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY`. Deployment receives their existing `OMG_R2_CACHE_*`
names and `OMG_R2_CACHE_SEED_RECEIPT`. No keys enter arguments, files, outputs
or uploaded receipts. The seed additionally checks that an independently signed,
already-expired temporary credential is refused by actual R2.
Before emitting that receipt, the producer creates and reads back the exact
canonical receipt bytes at both
`portable-v1/admission-v1/{recipe}/{producerRunId}-{producerAttempt}.json` and
`benchmark-v1/admission-v1/{recipe}/{producerRunId}-{producerAttempt}.json`.
The client derives these closed keys from the seed fields; the second object is
therefore known to exist when prefix-denial is checked. No extra seed schema
field or parent key is required.

## Portable PR caller

Keep the main secret-bearing configure step and its existing predicate. Add a
separate own-PR step in portable and portable-release. Install pinned sccache
0.18.0 when either route is selected; honor skip-cache in both routes. Only these
jobs need `contents: read`, `id-token: write`, `pull-requests: read`.

```yaml
- name: Configure PR read-only R2 cache
  id: r2-pr-cache
  if: >-
    github.event_name == 'pull_request' &&
    github.event.pull_request.head.repo.full_name == github.repository &&
    vars.OMG_R2_CACHE_ENABLED == 'true' &&
    vars.OMG_R2_PR_CACHE_ENABLED == 'true' && inputs.skip-cache != true
  env:
    OMG_R2_CACHE_ENABLED: ${{ vars.OMG_R2_CACHE_ENABLED }}
    OMG_R2_PR_CACHE_ENABLED: ${{ vars.OMG_R2_PR_CACHE_ENABLED }}
    OMG_R2_CACHE_ACCOUNT_ID: ${{ vars.OMG_R2_CACHE_ACCOUNT_ID }}
    OMG_R2_CACHE_BROKER_URL: ${{ vars.OMG_R2_CACHE_BROKER_URL }}
    GITHUB_TOKEN: ${{ github.token }}
  run: python3 scripts/ci-r2-cache.py --mode pr-read
```

The broker URL is the root HTTPS workers.dev endpoint read back by deployment.
The runner supplies its standard OIDC request URL/capability. The client obtains
the fixed audience and sends its ephemeral job token in `X-GitHub-Token`. After
verifying OIDC, the Worker forwards that token only to the fixed signed-ref PR
metadata endpoint; JWKS fetches never receive it. It is never persisted. This
uses authenticated job limits instead of a shared anonymous 60/hour egress limit.

The Worker fixes issuer/JWKS, RS256, audience, immutable repository/owner IDs,
public repository, workflow path, main base and current same-repository merge
SHA. Forks, stale merges, other workflows/events and arbitrary request bodies
cannot mint. A transactional SQLite ledger allows six distinct token identifiers
per run/attempt/source, with identical replay and one original expiry. Only
token hashes and timestamps persist, for at most 24 hours.

The client uses a unique daemon socket and a privately created canonical probe
cwd. Rust's literal cwd and CARGO environment hashing matter: the probe strips
CARGO variables consistently while application compilation keeps its normal
environment. It requires a fresh zero-counter READ_ONLY daemon, exactly one Rust
hit, zero writes/misses/errors/timeouts and exact original seed bytes. Credentials
exist only in the server environment and are masked immediately; compiler
clients and GitHub exports contain no credential triple.
Before starting a daemon, the client requires at least 40 minutes plus a
120-second setup/cleanup reserve remaining in the original 45-minute grant.
A delayed job with less time continues cold as `insufficient-lifetime`; no
refresh or ledger-window extension occurs.

On success the output is `enabled=true`, `disposition=verified-read`. Nonsecret
environment exports include mode, seed recipe, policy and expiry alongside the
sccache config/socket/wrapper. Report/cleanup steps run when either main or PR
setup enabled. Preserve the existing single-directory diagnostic upload and add
mode/recipe/policy/expiry to its nonsecret context. A known setup failure before
compilation returns a typed cold disposition with no wrapper export. Unconfirmed
daemon cleanup or partial activation is fatal. Compiler/test failures are never
retried into success.

## Live admission canaries

After reviewed trusted bootstrap, a controlled same-repository PR can run:

```sh
python3 scripts/ci-r2-cache.py --mode pr-read --verify-scope
```

Require this step's `enabled=true` and `disposition=verified-read`; exit zero alone
can represent deliberate cold fallback. This checks the cross-runner seed hit,
positive GET/HEAD of the exact seed marker and R2 denial of PUT, DELETE,
multipart part upload, listing, the proved-existing benchmark marker and absent/tampered session
tokens. Negative writes use a fresh harmless admission-canary key; a server
authorization failure records its nonsecret key and stays a failed promotion.
The seed workflow separately proves expired-token rejection without waiting.
The extra wrong-bucket request is diagnostic refusal only; it does not prove
that an object exists there or establish the parent's cross-bucket permissions.

Also require a real fork refusal/cold run, unexpected current claim refusal,
broker/metadata outage cold run, wrong source/recipe/seed byte controls, and
attempt-qualified stats/context artifacts downloaded by immutable ID/digest.
Keep the opt-in off until these pass. Measure same-source cold versus enabled
complete required pipelines, including probe/queue overhead; a cold fallback is
not a warm sample. Disable PR opt-in/issuance for rollback; do not rotate the
working main parent key merely to roll back optional PR reads.

Primary contracts: [GitHub OIDC](https://docs.github.com/en/actions/reference/security/oidc),
[PR metadata](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request),
[R2 local credential signing](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/),
[R2 temporary authority](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/),
[sccache S3](https://github.com/mozilla/sccache/blob/01c35e69b97f516c2ebfbdb418b5cd6277bde280/docs/S3.md),
[Durable Object SQL transactions](https://developers.cloudflare.com/durable-objects/api/storage-api/).

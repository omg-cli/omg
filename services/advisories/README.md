# OMG advisory service

This Worker serves public CVE records, the original Arch security issues, and CISA KEV annotations. OMG needs only its HTTPS URL. Package version comparisons remain in Rust's ALPM backend. A CVE identifier does not establish Arch or AUR package applicability.

D1 stores the current CVE index, provenance, feed checkpoints, leases, compact ingestion runs, baseline receipts, and KEV annotations. Private R2 stores payloads by SHA-256. A payload is persisted before its D1 pointer. Failed SQL may leave an unreferenced R2 object; SQL cannot reference a failed object write. Older CVE revisions cannot overwrite newer rejected records. Each production writer batch checks the current owner and lease expiry in a constraint guard inside the same D1 transaction. An expired or replaced writer cannot overwrite a snapshot, cursor, KEV membership or source error. Private content-addressed R2 orphans can remain after a fenced-out commit. All SQL values use prepared bindings. No client-supplied URL is fetched.

## HTTP contract

Public routes accept GET only. They require no Cloudflare account credentials.

| Route | Response |
| --- | --- |
| `/v1/status` | Schema version 1, archive bootstrap flag, per-feed completion, checked/fetched times, freshness and last ingestion error. |
| `/v1/arch/advisories` | `{schema_version:1,source:"arch-security",fetched_at,checked_at,complete,payload_sha256,payload_json:"exact upstream JSON string"}`. Returns 503 before a snapshot exists. |
| `/v1/cves/CVE-YYYY-NNNN` | Original CVE JSON string under `payload_json`, source provenance, optional KEV annotation and its independent freshness. Returns 404 for a missing record. |

`fetched_at` identifies payload acquisition. `checked_at` also advances after a trusted upstream 304 revalidation. A feed is stale after 30 minutes. The Arch snapshot remains available with `complete:false` when stale or after refresh failure. Original `Unknown` Arch issue states remain visible to Rust; snapshot completeness does not turn them into known package safety results.

CVE bootstrap completeness stays false in this implementation. Server-counted imported members and delta catchup are observable separately, but an independently verifiable full archive member manifest remains a prerequisite for any true bootstrap completeness claim. Unknown CVE schemas/states are preserved, marked unsupported and block bootstrap completion. This is a metadata boundary validator, not a full implementation of the CVE JSON Schema. CNA and ADP content is preserved without attempting package matching.

Private POST routes use a separate Worker secret `INGEST_TOKEN`, at least 32 random characters. Authorization is checked before reading the body or touching storage. HMAC verification uses Web Crypto rather than a handwritten timing comparison.

* `/internal/ingest` accepts `{source:"cve",records:[originalJsonString,...],baseline?:{digest,instance_id,session_id,endpoint}}`. Baseline imports require the binding returned by baseline start; server-side membership counts distinct successfully imported CVE IDs, separately from delta ingestion. Maximum eight records, 1 MiB each, 4 MiB aggregate request. This operator request limit is separate from the 32-record Cron batch limit.
* `/internal/baseline/start` accepts the archive digest and midnight timestamp, initializes the delta watermark, and clears bootstrap completeness. It returns a database instance ID, import session ID, digest and endpoint origin. Resume requests and operator state bind all four values. Repeating the same active receipt does not rewind progress.
* `/internal/baseline` accepts the operator archive receipt after post-import catchup. It verifies the instance/session/endpoint/digest binding, exact server-counted distinct imported membership, fresh completed delta checkpoint, post-import check time, and absence of unsupported records under the CVE writer fence. Success returns `imported`, `caught_up:true`, `archive_verified:false` and `bootstrap_complete:false`. The operator exhaustion assertion is recorded but cannot certify archive coverage.

Baseline membership is append-only. The writer inserts with `ON CONFLICT DO NOTHING`; migration `0002_baseline_member_counter.sql` maintains `baseline_receipt.accepted` with an `AFTER INSERT` trigger, so replay does not increment the distinct-member count. Member updates and deletes abort. Future member removal or rewriting requires an intentional migration that revises the triggers and reconciles the counter, rather than a new maintenance endpoint. Every import attempt clears its session's caught-up receipt even when all members were already present. Status reads the maintained count; finalization performs one membership count and rejects disagreement with the maintained counter or operator receipt.

Apply `0002` before deploying the Worker that reads the maintained counter. It reconciles existing sessions once and installs the triggers in the same migration batch. The already deployed `0001` migration is unchanged. The previous Worker remains compatible after `0002`, while the new Worker requires `0002` for correct counts.

The ingest secret is a trusted operator capability. SHA-256 is computed over the UTF-8 encoding of the exact `payload_json` string. Consumers can encode that string and verify the advertised hash before parsing it; JSON whitespace and key order are preserved. Invalid UTF-8 and UTF-8 BOMs are rejected. The service does not independently download the archive or verify every archive member. An authoritative publisher-bound manifest and exhaustive server membership comparison remain future work.

## Local checks

```sh
bun install --frozen-lockfile
bun test test
bun run check
bun run types
bun run dry-run
bunx wrangler d1 migrations apply DB --local
bunx wrangler dev --ip 127.0.0.1 --port 8794 --test-scheduled
```

The migration and service tests use real SQLite. A separate Miniflare test uses real local D1 `meta.rows_read` to bound mutation reads for 128 and 256 successful imports and status reads at both membership sizes. Its private fixture storage has a 50 MiB limit and is disposed and removed after each run. It measures query rows rather than wall-clock speed or production CPU. Archive tests use tiny checked-in ZIP fixtures with no remote writes. All Wrangler resource bindings above are local unless explicitly told otherwise.

## Provisioning and deployment

The dedicated service is deployed at `https://omg-advisories.latham.workers.dev`. The committed configuration binds its dedicated `omg-advisories` D1 database and private `omg-advisories-raw` R2 bucket. Do not substitute the unrelated platform database. The full historical CVE archive remains unimported and independently unverified; check `/v1/status` for current source freshness and progress. The Rust client validates the Arch snapshot separately from global CVE bootstrap status.

For an update to this deployment, apply reviewed migrations before deploying code that depends on them:

```sh
bun install --frozen-lockfile
bunx wrangler d1 migrations apply DB --remote
bun run types
bun run check
bun test test
bun run dry-run
bunx wrangler deploy --strict --secrets-file /absolute/private/advisories-secrets.json
```

The private JSON secret file contains `INGEST_TOKEN` and must be owned by the operator with mode `0600`. It is outside the repository. Preserve an existing secret when deploying without a secret update. A new account needs separately provisioned dedicated resources and matching configuration; validate its storage, write and CPU budgets before a historical import.

`secret put` creates a deployed Worker version. The bucket is private and has no configured public access. The public API is read only; its private write routes still require the operator secret. Do not store a Cloudflare account/API token in OMG or in this ingest secret.

The five-minute Cron reads only fixed official Arch, CISA and CVEProject URLs. The CVE rolling log is parsed incrementally with pinned `@streamparser/json` 0.0.26. It retains one event and the next bounded batch, validates the whole response before advancing the cursor, and rejects redirects. Event timestamp plus sorted position permits large events to span invocations. Failed batches replay idempotently. An expired ten-minute lease permits recovery. Falling behind the oldest retained delta requires a fresh archive reconciliation.

`CVE_BATCH_SIZE` is configured to 32, the validated ceiling, with a five-minute Cron and a 30,000 ms CPU cap. That admits at most 9,216 record changes per day; it does not establish zero backlog or immediate publication coverage. The upstream rolling log is about 39 MB, so both processing capacity and arrival rate matter. This configuration was accepted and exercised on the existing account without a subscription upgrade. Regenerate binding types and verify runtime limits when changing it or deploying elsewhere.

Bounds are explicit. CVE records are 1 MiB, snapshots 16 MiB, delta transport 64 MiB, a streamed event about 8 MiB, an archive 1 GiB compressed, a ZIP entry 1 MiB, and compression ratio 500. Oversized input fails partial. KEV normalized annotation JSON is capped below D1's 2,000,000-byte string limit. Updates replace its annotation index atomically only when content changes. Ingestion-run rows are retired after seven days. R2 retains historical payload hashes and SQL-failure orphans; a reviewed garbage collection policy remains future operator work.

## Archive bootstrap

Download the official full ZIP only after reserving local and Cloudflare capacity. The script accepts an existing archive and never downloads the corpus or extracts record paths. A sole `cves.zip` wrapper is decoded into a fixed private temporary file before the inner ZIP is scanned. Stored and DEFLATE wrappers require matching decoded size and CRC32, with a 1 GiB decoded limit and a 500:1 compression limit. Mixed or recursive wrappers and archives without CVE records are rejected. Source release filenames can include a doubled `.zip.zip` suffix. Select the exact official asset name, not an assumed filename.

The script fetches bounded metadata from the fixed official GitHub release API, matches asset size, and verifies its published SHA-256 before any ingest. Pinned `yauzl` 3.4.0 reads ZIP entries lazily. It validates CVE filename/year/bucket consistency, entry size and compression bounds. Paths are never extracted. An atomic local resume file advances only after an accepted HTTP batch. Replay after a lost response is safe.

```sh
bun run bootstrap --help
bun run bootstrap \
  --archive /absolute/operator-data/2026-11-13_all_CVEs_at_midnight.zip.zip \
  --asset 2026-11-13_all_CVEs_at_midnight.zip.zip \
  --release-tag cve_2026-11-13_0100Z \
  --state /absolute/operator-data/advisories.bootstrap-state.json \
  --max-records 1000 --dry-run
```

Use the actual official release tag returned by GitHub rather than copying an example date indefinitely. A dry run reads/verifies up to the record budget and never writes HTTP or a resume file. For ingestion, omit `--dry-run` and add `--endpoint https://DEPLOYED-WORKER` and `--token-file /absolute/private/ingest-token`. Alternatively provide the separate token through the `INGEST_TOKEN` environment variable. Token files must have private permissions.

Repeat with the same archive/state until `exhausted:true`. Default admission is 1,000 records per invocation with a one-second batch delay. `--max-records` and `--delay-ms` bound a wave; transient HTTP errors back off at most five attempts. D1 free-tier daily writes are insufficient for an unpaced full backfill of two indexed rows per CVE plus metadata. Schedule waves or confirm a paid budget rather than treating HTTP success as an unbounded quota.

After the last import, let Cron catch up and run the same command with `--finalize`. Finalization fails while the delta checkpoint is incomplete/stale, predates the import's finish, has a mismatched instance/session/endpoint, or disagrees with server-counted imported members. Successful finalization reports imported and caught-up state but keeps `archive_verified:false` and `bootstrap_complete:false`. Full bootstrap is unfinished until independently verifiable archive coverage exists. Preserve the archive digest and compact receipt after retiring obsolete scratch data. Use one operator per resume file. Existing resume files without a database/session/endpoint binding are rejected; do not reuse them against a new database. Each archive scan owns a private snapshot with a 1 GiB compressed budget and hashes those exact bytes before parsing. A wrapped archive needs up to another 1 GiB for the verified inner ZIP, for a 2 GiB temporary file budget plus bounded record buffers. Both files are removed when the scan ends. Resume positions index the selected inner or flat corpus, while the official outer digest remains the session identity. Legacy resume files marked exhausted with zero accepted records are rejected; start with a new state file to rescan the archive. Keep space for that temporary copy on C:. A full import has not been run in this change.

## Primary references

* [Official CVEProject download cadence, baseline/delta naming, and rolling log](https://github.com/CVEProject/cvelistV5/blob/main/README.md).
* [Official Arch issues](https://security.archlinux.org/issues/all.json).
* [Official CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
* [D1 limits and batch semantics](https://developers.cloudflare.com/d1/platform/limits/).
* [Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).
* [yauzl lazy entry API](https://github.com/thejoshwolfe/yauzl).
* [Streaming JSON parser API](https://github.com/juanjoDiaz/streamparser-json/tree/main/packages/plainjs).

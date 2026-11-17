# OMG advisory service

This Worker serves public CVE records, Arch security issues, CISA KEV annotations, EPSS enrichment and vendor-specific assessments for 13 runtimes. An additional npm package assessment covers the Pi coding harness. OMG needs only its HTTPS URL. Arch package version comparisons remain in Rust's ALPM backend. A CVE identifier alone does not establish package or runtime applicability.

D1 stores the current CVE index, provenance, feed checkpoints, leases, compact ingestion runs, baseline receipts, and KEV annotations. Private R2 stores payloads by SHA-256. A payload is persisted before its D1 pointer. Failed SQL may leave an unreferenced R2 object; SQL cannot reference a failed object write. Older CVE revisions cannot overwrite newer rejected records. Each production writer batch checks the current owner and lease expiry in a constraint guard inside the same D1 transaction. An expired or replaced writer cannot overwrite a snapshot, cursor, KEV membership or source error. Private content-addressed R2 orphans can remain after a fenced-out commit. All SQL values use prepared bindings. No client-supplied URL is fetched.

## HTTP contract

Public routes accept GET only. They require no Cloudflare account credentials.

| Route | Response |
| --- | --- |
| `/v1/status` | Schema version 1, archive bootstrap flag, per-feed completion, checked/fetched times, freshness and last ingestion error. |
| `/v1/arch/advisories` | `{schema_version:1,source:"arch-security",fetched_at,checked_at,complete,payload_sha256,payload_json:"exact upstream JSON string"}`. Returns 503 before a snapshot exists. |
| `/v1/cves/CVE-YYYY-NNNN` | Original CVE JSON string under `payload_json`, source provenance, optional KEV annotation and its independent freshness. Returns 404 for a missing record. |
| `/v1/cves/recent?limit=100&cursor=...` | Latest stored revisions modified within a rolling 30-day window, metadata only, newest first. At most 100 rows; opaque next cursor fixes the window for pagination. Independent CVE completeness and freshness remain explicit. |
| `/v1/epss/CVE-YYYY-NNNN` | FIRST exploitation probability, percentile and bounded history, with explicit missing/unavailable states. |
| `/v1/runtimes/{runtime}?version=...&vendor=...&os=...&arch=...` | Exact identity, coverage, disclosed findings, applicability gaps and source content hashes. All four parameters are mandatory and unique. |

`fetched_at` identifies payload acquisition. `checked_at` also advances after a trusted upstream 304 revalidation. A feed is stale after 30 minutes. The Arch snapshot remains available with `complete:false` when stale or after refresh failure. Original `Unknown` Arch issue states remain visible to Rust; snapshot completeness does not turn them into known package safety results.

Successful fresh public data responses use full-representation SHA-256 ETags and the Workers Cache API. Cache lifetime is at most 60 seconds and ends before any included source check becomes stale. Fresh partial datasets retain `complete:false`; caching does not certify coverage. `/v1/status`, private or authenticated/cookie-bearing requests, errors and stale data return `Cache-Control: no-store`. `If-None-Match` supports conditional 304 responses; `Cache-Control: no-cache` or `max-age=0` forces an origin read for an update. Cache failures fall back to D1/R2. The Cache API is local to each Cloudflare data center, so cold requests still read storage; no production latency guarantee is implied.

The recent view contains upstream modification times in `[as_of - 30 days, as_of]`. It includes rejected revisions and excludes future-dated entries. Older records remain directly retrievable; no CVEs or raw payloads are deleted. It is a latest-revision view rather than an immutable event history. Newer revisions can move between pages: clients must overlap subsequent refreshes and cannot infer a complete corpus from one traversal. Limits are 1–100, default 100; cursors expire after one hour. Unknown/duplicate parameters and malformed cursors fail with 400. Encode `next_cursor` as a query parameter using `URLSearchParams` or equivalent.

Apply `0003_recent_cves.sql` before deploying the recent-view route. It adds a modification-time/ID index without changing existing data or writers. Index creation has a one-time read/write cost proportional to existing records; include that migration and continuing index maintenance in the account's quota/credit budget before remote execution. The migration and cache route were deployed and verified on 2026-11-16 as Worker version `1ae795ee-841f-4f78-9a99-da9ee600e18e`; the production page query read two rows for two records, and live warm/conditional/revalidation/private-isolation checks passed. See the compact receipt in `docs/superpowers/plans/2026-11-16-advisory-cache-production-receipt.md` at the repository root. Runtime assessment implementation below requires migration `0005_runtime_sources.sql`; its local test evidence does not establish production deployment.

CVE bootstrap completeness remains false until the server independently reconciles every expected publisher Git member and original payload identity, then verifies completed delta catchup. Operator counts and ZIP exhaustion alone cannot certify archive coverage. Unknown CVE schemas/states are preserved, marked unsupported and block bootstrap completion. This is a metadata boundary validator, not a full implementation of the CVE JSON Schema. CNA and ADP content is preserved without attempting package matching.

Private POST routes use a separate Worker secret `INGEST_TOKEN`, at least 32 random characters. Authorization is checked before reading the body or touching storage. HMAC verification uses Web Crypto rather than a handwritten timing comparison.

* `/internal/ingest` accepts `{source:"cve",records:[originalJsonString,...],baseline?:{digest,instance_id,session_id,endpoint}}`. Baseline imports require the binding returned by baseline start; server-side membership counts distinct successfully imported CVE IDs, separately from delta ingestion. Maximum eight generic records or 64 distinct supported records with a baseline binding, 3 MiB of original UTF-8 JSON each, 4 MiB for the complete encoded request. Baseline bulk persistence uses at most six concurrent R2 puts, drains every started write before returning failure, and commits pointers and membership together under the writer fence. Generic and delta ingestion retain four-way concurrency.
* `/internal/cve-refresh` accepts exactly `{}` under the ingest credential. It runs one fixed official CVE delta batch of at most 32 records under the same source lease and commit fence, returning the actual cursor and completion state. Serial operator calls can drain backlog between scheduled runs; they cannot change archive certification or bootstrap completeness.
* `/internal/baseline/start` accepts the archive digest and midnight timestamp, initializes the delta watermark, and clears bootstrap completeness. It returns a database instance ID, import session ID, digest and endpoint origin. Resume requests and operator state bind all four values. Repeating the same active receipt does not rewind progress.
* `/internal/baseline` accepts the operator archive receipt after post-import catchup. It verifies the instance/session/endpoint/digest binding, exact server-counted distinct imported membership, fresh completed delta checkpoint, post-import check time, and absence of unsupported records under the CVE writer fence. Success returns `imported`, `caught_up:true`, `archive_verified:false` and `bootstrap_complete:false`. The operator exhaustion assertion is recorded but cannot certify archive coverage.

Baseline membership is append-only. The writer inserts with `ON CONFLICT DO NOTHING`; migration `0002_baseline_member_counter.sql` maintains `baseline_receipt.accepted` with an `AFTER INSERT` trigger, so replay does not increment the distinct-member count. Member updates and deletes abort. Future member removal or rewriting requires an intentional migration that revises the triggers and reconciles the counter, rather than a new maintenance endpoint. Every import attempt clears its session's caught-up receipt even when all members were already present. Status reads the maintained count; finalization performs one membership count and rejects disagreement with the maintained counter or operator receipt.

An import processes at most four distinct CVE IDs concurrently. Revisions of the same ID retain their request order, including rejection and conflicting-revision checks. Every started group settles before the writer lease is released, even when another group fails. A failed request can therefore leave successful records committed; the operator advances its resume position only after a successful response and safely replays otherwise. The eight-record and four-MiB request limits remain in force.

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

The five-minute Cron reads only fixed official Arch, CISA and CVEProject URLs. The CVE rolling log is parsed incrementally with pinned `@streamparser/json` 0.0.26. It retains one event and the next bounded batch, validates the whole response before advancing the cursor, and rejects redirects. Event timestamp plus sorted position permits large events to span invocations. Scheduled refreshes and operator imports share a bounded ingestion routine: at most four distinct CVE IDs run concurrently, revisions of one ID remain serial, and all started work settles before a failure releases the writer lease. The delta cursor advances only after the entire selected batch succeeds. Failed batches replay idempotently. An expired ten-minute lease permits recovery. Falling behind the oldest retained delta requires a fresh archive reconciliation.

`CVE_BATCH_SIZE` is configured to 32, the validated ceiling, with a five-minute Cron and a 30,000 ms CPU cap. That admits at most 9,216 record changes per day; it does not establish zero backlog or immediate publication coverage. The upstream rolling log is about 39 MB, so both processing capacity and arrival rate matter. This configuration was accepted and exercised on the existing account without a subscription upgrade. Regenerate binding types and verify runtime limits when changing it or deploying elsewhere.

Bounds are explicit. CVE records are 3 MiB, snapshots 16 MiB, delta transport 64 MiB, a streamed event about 8 MiB, an archive 1 GiB compressed, a CVE ZIP entry 3 MiB, and compression ratio 500. Oversized input fails partial. KEV normalized annotation JSON is capped below D1's 2,000,000-byte string limit. Updates replace its annotation index atomically only when content changes. Ingestion-run rows are retired after seven days. R2 retains historical payload hashes and SQL-failure orphans; a reviewed garbage collection policy remains future operator work.

## EPSS enrichment

`GET /v1/epss/CVE-YYYY-NNNN` enriches an already imported CVE with [FIRST EPSS](https://www.first.org/epss/data). It returns the score, percentile, score date, attribution and up to 30 days of history as of the response's `as_of` time. `scored`, `missing` and `unavailable` are separate states; a real zero is retained as zero, and a failed lookup never supplies a zero or claims safety. Scores older than two days remain unavailable. EPSS forecasts observed exploitation over the next 30 days; it does not establish package applicability or override CISA KEV, CVEs or required consent.

The bounded fixed-origin lookup uses the [official time-series API](https://api.first.org/epss/) for individual requested CVEs. It does not mirror the whole EPSS dataset through that API. D1 caches successful results for six hours, backs off failures for one minute and retains the last successful history on upstream failure. Lease fencing prevents expired writers from replacing that history. Public responses use ETags and at most 60 seconds of edge caching. Unknown CVEs do not trigger upstream queries. Apply migration `0004_epss_cache.sql` before deploying this route. The [FIRST service terms](https://www.first.org/about/policies/terms) permit preventative cybersecurity use; attribution is included in every result.

Migration 0004 and Worker version `2d494aaa-c66b-4333-b3dd-a92609663004` are deployed from `440de96f`. Live EPSS lookup, warm-body identity, conditional 304, D1 cache reuse and invalid/unknown request controls pass; see `docs/superpowers/plans/2026-11-16-epss-enrichment.md` at the repository root. The underlying CVE baseline remains incomplete, so CVEs missing from that baseline receive unavailable coverage rather than an invented EPSS score.

## Runtime and Pi coding-harness assessments

Apply `0005_runtime_sources.sql` before deploying the runtime route. The response is `{schema_version:1,identity:{runtime,vendor,version,os,arch},checked_at,coverage,findings,gaps,sources}`. Coverage is `assessed`, `partial` or `unknown`; it describes applicability of the selected disclosed-advisory sources. It does not assert that undisclosed vulnerabilities do not exist. Findings retain CVE-less vendor identifiers and distinguish `applicable` from `possible`. Every finding includes a public HTTPS reference. Clients must display gaps and obtain informed acknowledgment for incomplete assessments rather than silently treating an empty finding list as safety.

Versions must identify an exact upstream release. Aliases, mismatched vendors and unsupported version forms produce `unknown`. Allowed operating systems are `linux`, `macos`, `windows`; architectures are `x86_64`, `aarch64`. The identity is echoed exactly. OS and architecture remain part of that identity even where the vendor source describes all platforms. No CPE guesses, `npm/node`, `PyPI/python`, Ruby gems or Rust crates stand in for an interpreter or toolchain. Pi is an npm-installed coding harness; its optional package assessment is separate from the 13 runtime adapters.

| Runtime / vendor parameter | Authoritative disclosure input and applicability limit |
| --- | --- |
| `node` / `nodejs` | [Node security-wg core index](https://github.com/nodejs/security-wg/tree/main/vuln/core): vulnerable ranges minus patched ranges, preserving core IDs without CVEs. |
| `go` / `golang` | [Go vulnerability database through OSV](https://vuln.go.dev/): separate exact-version `Go/stdlib` and `Go/toolchain` queries, including every page. |
| `pi` / `earendil-works` | [OSV exact package queries](https://google.github.io/osv.dev/post-v1-query/): npm `@earendil-works/pi-coding-agent`, matching the installed package identity. |
| `python` / `cpython` | [PSF CPython records](https://github.com/psf/advisory-database) plus [CVEProject vendor records](https://github.com/CVEProject/cvelistV5): numeric vendor applicability where available; Git-only ranges remain possible. Bundled python-build-standalone libraries remain incomplete. |
| `ruby` / `ruby-lang` | [RubySec MRI interpreter records](https://github.com/rubysec/ruby-advisory-db/tree/master/rubies/ruby): genuine YAML and Ruby version requirements. Bundled gems remain incomplete. |
| `rust` / `rust-lang` | [RustSec toolchain records](https://github.com/RustSec/advisory-db/tree/main/rust): genuine TOML for `std`, `cargo`, `rustdoc`; supplemental coverage does not certify every compiler or bundled-tool component. |
| `bun` / `oven-sh` | [Bun publisher advisories](https://github.com/oven-sh/bun/security/advisories): exact product names and supported version ranges. |
| `deno` / `denoland` | [Deno publisher advisories](https://github.com/denoland/deno/security/advisories): exact runtime names and supported version ranges. |
| `erlang` / `erlang` | [OTP publisher advisories](https://github.com/erlang/otp/security/advisories) and [OTP component version table](https://github.com/erlang/otp/blob/master/otp_versions.table): whole-OTP and application versions are distinct; four-component versions and maintenance branches are retained. |
| `php` / `php` | [PHP publisher advisories](https://github.com/php/php-src/security/advisories): maintenance-branch fixes are selected before comparison. Unmapped extension versions remain possible. |
| `java` / `temurin` | [Adoptium Temurin VDR](https://github.com/adoptium/temurin-vdr-generator): official digest-verified CycloneDX asset. Requires a patch identity, retains the caller's build suffix and uses enumerated upstream affected releases; omitted builds/components remain incomplete. |
| `dotnet` / `microsoft` | [Microsoft release metadata](https://github.com/dotnet/core/tree/main/release-notes) maps the exact SDK to its runtime/ASP.NET components before comparing vendor CVE records. Later SDK-only and ASP.NET-only security updates remain candidates even when the bundled runtime version is unchanged. SDK `9.0.100` is never compared as runtime `9.0.100`. Ambiguous mappings remain unknown. |
| `zig` / `ziglang` | [Zig publisher advisories](https://github.com/ziglang/zig/security/advisories): disclosures are useful, but a complete applicability feed is not established. Empty results remain unknown. |
| `swift` / `swiftlang` | [Swift publisher advisories](https://github.com/swiftlang/swift/security/advisories): disclosures are useful, but a complete applicability feed is not established. Empty results remain unknown. |

Inputs come from fixed origins. GitHub repository archives are pinned to an upstream commit before selection; no paths are extracted. ZIP compressed input is limited to 16 MiB, selected expansion to 8 MiB, individual selected files to 1 MiB, selected files to 4,096 and all archive entries to 32,768. Native ZIP CRC and overlap checks remain enabled. YAML, TOML, npm and Ruby Gem requirements use pinned maintained parsers rather than handwritten substitutes. Ruby's genuine Gem comparator preserves four-component patch levels, pessimistic requirements and exclusions; an old fix such as `>=1.8.6.111` correctly excludes Ruby 3.3.0. Paginated results are limited to 20 pages and 8 MiB of accumulated content; hitting a bound produces incomplete coverage. An invocation has a 25-second source deadline and a 768-subrequest budget; unauthenticated upstream rate limits can still produce unknown coverage. CVE lookups run eight at a time and retain at most 512 identifiers under the same byte budget.

D1 points to private content-addressed R2 snapshots. Successful source checks are fresh for 30 minutes; failures back off for one minute. Expired or replaced lease holders cannot update D1. Transport failures, malformed source replacements and partial CVE applicability refreshes preserve the last good pointer. A source's SHA-256 covers its underlying source content, independent of request/retrieval timestamps. Revalidation of unchanged content keeps the hash stable. Source revision and source checked time remain separate fields. No known historical CVE is discarded because it is older than the recent-view window.

Runtime responses contain at most 512 findings, 64 gaps, 16 sources and 2 MiB. Only fresh `assessed` reports receive public edge caching, for at most 60 seconds. Partial, unknown, stale and failed-source reports use `no-store`. `Cache-Control: no-cache` bypasses the edge cache and rereads D1/R2, allowing the client to compare evidence again after a user accepts a warning. For GitHub API-dependent sources, public reads reuse genuinely fresh snapshots without changing their original timestamps. Forced reads with five minutes or less remaining attempt actual upstream revalidation; only a successful check renews `checked_at`. These public checks use anonymous GitHub requests and can encounter quota limits. Failures preserve the last successful payload and timestamp with explicit coverage gaps. Authenticated scheduled refreshes force upstream checks; raw-file and OSV revalidation behavior remains unchanged. Contention or unusually long operations can still exhaust the 30-minute validity window and cause a safe refusal.

### Scheduled GitHub source refresh

The public GitHub REST quota is [60 requests/hour per originating IP](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), so shared Worker egress can exhaust it even for public feeds. HTTP 403/429 diagnostics expose only bounded numeric remaining/reset/retry headers; error bodies are discarded. This distinguishes known quota exhaustion from other forbidden responses without reflecting credentials.

`.github/workflows/advisory-refresh.yml` warms the ten GitHub API-dependent vendor feeds on trusted changes to `main`, every 30 minutes and manual dispatch on `main`. Its checkout is pinned and does not persist credentials; its sole token permission is `contents: read`. The Python standard-library driver posts only to the fixed advisory Worker origin, verifies TLS, disables proxy inheritance, refuses redirects and bounds response size. It continues through all approved feeds and fails the job if a required source refresh is incomplete. A successful source refresh can still have `coverage:unknown` when vendor applicability is incomplete; warming a feed does not certify a version as safe. Scheduler delays or upstream failures can leave a snapshot stale; freshness is never extended to hide that gap.

Set a new independent `RUNTIME_REFRESH_SECRET` in both the advisory Worker and the repository's Actions secrets. Use 32–256 random ASCII letters, digits, underscores or hyphens. This secret authorizes runtime feed refresh and publisher baseline verification; it does not authorize CVE imports, delta catchup or baseline receipt creation/finalization. Preserve the existing `INGEST_TOKEN` unchanged. No secret values belong in committed files or command output.

The private route accepts exactly `{runtime,github_token}` under `Authorization: Bearer RUNTIME_REFRESH_SECRET`, checks authentication before reading the bounded 4 KiB body, and permits only fixed refresh profiles. The job supplies its ephemeral `ghs_` GitHub installation token, never a personal token. That token is attached only to exact allowlisted `api.github.com` GET routes with manual redirect handling; it is absent from archive/raw hosts, release assets and asset redirects. It is never written to D1/R2, returned or logged; reflected credentials are rejected and transport errors are redacted. No GitHub credential is stored as a Cloudflare secret. The response reports source success separately from incomplete runtime applicability. These jobs reuse the same source producers, cache keys, content hashes, leases and fences as public assessments, without a second advisory ingestion format.

After the Worker is deployed and both copies of the refresh secret are configured, run the workflow on `main` and verify fresh source timestamps and complete source receipts through the public routes. Local tests prove the wiring and credential boundaries; they do not establish that the hosted Actions job has run successfully.

[Cloudflare Zero Wire](https://radar.cloudflare.com/zero-wire) is currently **link-only / redistribution permission required**. Public access is not permission to mirror the content commercially: [Radar dataset licensing](https://developers.cloudflare.com/radar/) must be checked before enabling ingestion. No Zero Wire payload is mirrored, and startup credits do not change content licensing. Publisher CVE-less advisories remain available through the adapters above.

The local suite exercises affected/fixed/unknown states across all 14 routes, source freshness and hash changes, OSV/publisher pagination, maintenance branches, exact SDK mappings, partial refresh preservation and real SQLite lease fences. A real workerd test reads a DEFLATE vendor archive, parses YAML, stores D1/R2 evidence and verifies partial responses bypass edge caching. These tests do not prove completeness of external disclosure programs.

## Archive bootstrap

Download the official full ZIP only after reserving local and Cloudflare capacity. The script accepts an existing archive and never downloads the corpus or extracts record paths. A sole `cves.zip` wrapper is decoded into a fixed private temporary file before the inner ZIP is scanned. Stored and DEFLATE wrappers require matching decoded size and CRC32, with a 1 GiB decoded limit and a 500:1 compression limit. Mixed or recursive wrappers and archives without CVE records are rejected. Source release filenames can include a doubled `.zip.zip` suffix. Select the exact official asset name, not an assumed filename.

The script fetches bounded metadata from the fixed official GitHub release API, matches asset size, and verifies its published SHA-256 before any ingest. Pinned `yauzl` 3.4.0 reads ZIP entries lazily. It validates CVE filename/year/bucket consistency, entry size and compression bounds. Paths are never extracted. An atomic local resume file advances only after an accepted HTTP batch. Replay after a lost response is safe.

```sh
bun run bootstrap --help
bun run bootstrap \
  --archive /absolute/operator-data/2026-11-13_all_CVEs_at_midnight.zip.zip \
  --asset 2026-11-13_all_CVEs_at_midnight.zip.zip \
  --release-tag cve_2026-11-13_0000Z \
  --state /absolute/operator-data/advisories.bootstrap-state.json \
  --max-records 1000 --dry-run
```

Use the actual official release tag returned by GitHub rather than copying an example date indefinitely. A dry run reads/verifies up to the record budget and never writes HTTP or a resume file. For ingestion, omit `--dry-run` and add `--endpoint https://DEPLOYED-WORKER` and `--token-file /absolute/private/ingest-token`. Alternatively provide the separate token through the `INGEST_TOKEN` environment variable. Token files must have private permissions.

Repeat with the same archive/state until `exhausted:true`. Default admission is 1,000 records per invocation with no artificial batch delay. Requests remain serial: each complete envelope is at most 4 MiB and 64 records, the server retains its writer fence, and at most four R2 writes run concurrently inside that request. Supported distinct baseline IDs use one indexed old-state lookup and one fenced atomic metadata batch, including original membership and Git identity. All equal-revision conflicts are checked before R2 writes start, and all started writes settle before an error releases the writer. Duplicate IDs and unsupported records retain the existing serial-per-ID preservation path. Generic delta ingestion is unchanged. `--max-records` (up to 100,000) and `--delay-ms` bound a wave. Connection loss, response-body interruption and transient HTTP errors retry the exact same body at most five times with bounded backoff; `Retry-After` is respected up to 30 seconds. Permanent failures stop the wave. The checkpoint advances only after the server acknowledges the exact sent record count. Progress and elapsed time are emitted without credentials.

Start with `--max-records 256 --delay-ms 0` to measure up to four serial requests before increasing the wave budget. The previous eight-record batches and one-second delay alone imposed 12,500 seconds per 100,000 records; removing that delay and redundant metadata round trips does not predict actual D1/R2 throughput. [Cloudflare's D1 limits](https://developers.cloudflare.com/d1/platform/limits/) and [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) still apply. Paid Workers currently permit more subrequests than D1's per-invocation query budget; this operator does not raise either service limit or add concurrent HTTP writers. D1 free-tier daily writes are insufficient for an unpaced full backfill of two indexed rows per CVE plus metadata. Schedule waves or verify account coverage rather than treating HTTP success as an unbounded quota.

If the private state file is lost, retrieve the existing instance/session binding through the authorized operator process and replay the original byte-verified archive from zero. Never infer a local ZIP position from the database's imported count: directory entries, ordering and already-imported members make those different quantities. A new missing state path can use `--resume-instance INSTANCE --resume-session SESSION` with the same endpoint, release and asset. Recovery records `accepted:0`, `next_entry:0`, `exhausted:false`, `finished_at:null`; the server must return the exact requested digest/instance/session/endpoint. These flags refuse an existing state file. Replayed ingestion is idempotent. Recovery establishes no archive certification, and `--yes` or an operator count cannot certify completeness.

After the last import, let Cron catch up and run the same command with `--finalize`. Finalization fails while the delta checkpoint is incomplete/stale, predates the import's finish, has a mismatched instance/session/endpoint, or disagrees with server-counted imported members. Finalization alone keeps `archive_verified:false` and `bootstrap_complete:false`.

The separate authenticated `POST /internal/baseline/verify` route pins the exact official midnight release asset and publisher commit, traverses bounded Git trees on the server, and reconciles every expected CVE ID/Git blob identity against the immutable original import ledger. Newer delta records do not overwrite those original baseline identities. The route accepts no operator manifest or claimed member count. Authorize it with the separate `RUNTIME_REFRESH_SECRET`, not `INGEST_TOKEN`, and provide only an ephemeral `ghs_` GitHub installation token for the allowlisted publisher API. Both credentials are passed through the operator child's environment and never through command arguments or state files.

```sh
bun scripts/verify-baseline.ts --state /absolute/operator-data/advisories.bootstrap-state.json \
  --release-tag cve_2026-11-13_0000Z --asset 2026-11-13_all_CVEs_at_midnight.zip.zip \
  --max-steps 20 --delay-ms 0
```

Repeat bounded proof waves while the phase is `traversing` or `reconciling`. `awaiting_import` requires the original archive replay to finish, including legacy imported rows missing original Git identity. `awaiting_catchup` requires a fresh completed delta checkpoint after import and finalization. Only a server response with phase `verified`, equal positive expected/verified counts, no pending trees and `archive_verified:true` is a successful proof. A local archive count or matching samples remains diagnostic evidence, not certification.

Preserve the archive digest and compact receipts after retiring obsolete scratch data. Use one operator per resume file and do not overlap archive scans inside a shared storage budget. Existing resume files without a database/session/endpoint binding are rejected; do not reuse them against a new database. Each archive scan owns a private snapshot with a 1 GiB compressed budget and hashes those exact bytes before parsing. A wrapped archive needs up to another 1 GiB for the verified inner ZIP, for a 2 GiB temporary file budget plus bounded record buffers; budget the retained original archive in addition. Both temporary files are removed when the scan ends. Resume positions index the selected inner or flat corpus, while the official outer digest remains the session identity. Legacy resume files marked exhausted with zero accepted records are rejected; start with a new state file to rescan the archive. Keep operator scratch on C:. Check live `/v1/status` for actual imported and certified state; source changes and local tests do not establish a completed production import.

## Primary references

* [Official CVEProject download cadence, baseline/delta naming, and rolling log](https://github.com/CVEProject/cvelistV5/blob/main/README.md).
* [Official Arch issues](https://security.archlinux.org/issues/all.json).
* [Official CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
* [D1 limits and batch semantics](https://developers.cloudflare.com/d1/platform/limits/).
* [Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).
* [yauzl lazy entry API](https://github.com/thejoshwolfe/yauzl).
* [Streaming JSON parser API](https://github.com/juanjoDiaz/streamparser-json/tree/main/packages/plainjs).

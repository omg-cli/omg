# Local verification receipt

Run date 2026-11-13 UTC. Owner is the advisory-service implementation agent. Scope is `services/advisories/**`. No Cloudflare resources, secrets, deployed Workers or remote databases were changed. The full corpus ZIP was not downloaded.

TDD first failed on the public status contract. Expected HTTP 200, received 503. The implementation then passed that behavior against the real SQLite migration. A subsequent actual workerd run exposed unsupported `redirect:'error'`; source fetches now use Workers-supported `manual` and reject redirect responses, with a regression test.

Final unit/integration checks are 19 passing tests, 68 assertions, covering actual SQLite migration/prepared statements, raw-before-index ordering, old/rejected revision protection, unknown-schema replay, leases, checkpoint failure/replay, read-only routing, authorization-before-body, bounded input, Arch 304/stale handling, baseline start/catchup/finalization, KEV removals/rollback, streaming-delta pagination/continuity, and lazy ZIP hash/path/budget/resume failures.

`bun run check`, `bun run types` with binding-only generation, and `bun run dry-run` passed locally. Versions remain Wrangler 4.160.0, TypeScript 7.0.2, Workers types 5.20261110.1 and Bun types 1.3.10. New runtime dependencies are exactly `@streamparser/json` 0.0.26 and `yauzl` 3.4.0, with yauzl typings 3.4.0. The ZIP library is confined to the local operator and is not bundled into the Worker.

A read-only live-source probe consumed the current official delta log, 39,158,958 bytes, using the streaming parser and selected four records in 1,611 ms on this machine. This includes local network time and does not measure Cloudflare CPU or promise production throughput.

Wrangler's local D1 migration executed successfully. A real local workerd scheduled invocation then ingested fixed upstream feeds into local D1/R2. `/v1/status` reported fresh complete Arch and KEV feeds, incomplete CVE bootstrap, and no ingestion errors. `/v1/arch/advisories` returned schema 1, source `arch-security`, `complete:true`, 2,444 original issues, and SHA-256 `aaba5defa65cdc4468546cb775b0aac06180fab40219103e3c2ad699ea2f2301`. The local CVE index contained four published records and kept bootstrap false. These source snapshots were local generated verification data, not remote Cloudflare writes.

Local scratch owner is this service. Its `.wrangler` runtime state has a 100 MiB budget and may be retired after the implementing owner has reviewed this receipt. The local server was stopped. Production resource binding, account billing, remote migrations, authentication setup, deployment and full-corpus bootstrap remain the deploying owner's gates. Independent review has not been performed by this implementation agent.

## Integrity fix round 12

The current implementation supersedes the baseline certification and parsed-object wire contracts above. The old 19 tests remain represented. The changed baseline test now checks server-counted import and catchup while requiring `archive_verified:false` and `bootstrap_complete:false`. Full corpus bootstrap remains unfinished pending an authoritative publisher-bound exhaustive archive member manifest. No remote schema or Worker deployment was performed in this round.

The new regression tests failed before production changes. The stale snapshot test expected checkpoint `2026-11-13T02:11:00.000Z` but received the expired writer's `2026-11-13T02:00:00.000Z`. Raw wire payload expected the original formatted JSON string but received `undefined`. BOM rejection expected a rejected promise but received a resolved one. The inflated baseline receipt expected HTTP 400 but received HTTP 200 with an unaccounted `accepted:400000` assertion.

Writer-scoped stores now prepend a lease owner and expiry constraint to every production mutation batch. SQL execution time checks expiry in production; tests can inject a deterministic clock. SQLite transactions prove stale/expired owner rejection rolls back snapshot/cursor/error/KEV writes. The design relies on D1 batch transaction rollback, as documented in [Cloudflare's D1 batch API](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch). Content-addressed R2 writes precede the transaction and may leave unreferenced objects when the guard rejects a commit.

Database instances and baseline sessions bind resume state to digest and endpoint origin. Distinct successfully imported CVE members are counted by the server. Replays do not inflate membership. Fresh database or endpoint reuse and a wrong session are rejected. Operator exhaustion and count assertions do not independently certify publisher archive coverage. New imports clear the session's caught-up receipt.

Public CVE and Arch envelopes expose exact UTF-8 JSON text as `payload_json`. Hashes cover that string's UTF-8 bytes, including original whitespace and key order. BOMs and malformed UTF-8 are rejected. Archive scanning owns a private temporary copy, admits at most 1 GiB compressed bytes, hashes that snapshot, parses it and removes it when finished. A regression mutates the original archive after the first eight records and still receives all nine verified snapshot records. The new nine-record ZIP fixture is synthetic test data only.

Final round checks are recorded below after the final run. No full CVE corpus was downloaded and no production data was imported. Independent correctness review remains a release gate for the coordinating owner.

Final integrity-round run passed 27 tests and 91 assertions with `bun test test`, `bun run check`, `bun run types` and `bun run dry-run`. The final dry run packaged 84.44 KiB, 18.29 KiB gzip. It did not upload or deploy. This round performed no native build, worktree operation, Git mutation, remote migration or production import. Independent review is pending with the coordinating owner. The current source hash is reported to that owner separately.

## Full ingest envelope budget follow-up

Independent review reproduced an operator batch that measured only `{source,records}` while the transmitted request also included its baseline binding. The new real ZIP regression first failed with `Expected: <= 4194304`, `Received: 4194406` bytes. It constructs four valid 1,048,500-byte CVE records in a temporary stored ZIP and checks the actual POST body, including database/session/digest/endpoint fields.

The scanner now receives the complete batch serializer up front, checks UTF-8 bytes of the resulting body, and sends that exact serialized string. The operator's HTTP helper transmits it unchanged. An individual record whose complete envelope cannot fit fails before sending. There is no reduced record-count limit or guessed padding allowance. The regression now delivers all four original records, advances accepted to four, and exhausts the archive using only bodies within the limit. Its temporary ZIP is removed after the test.

Final follow-up checks passed 28 tests and 98 assertions, `bun run check`, and `bun run dry-run`. The existing 27 tests remain; only archive serializer API adaptations were required. The Worker bundle remains 84.44 KiB, 18.29 KiB gzip because these changes affect the local operator. No deployment or remote write occurred. Independent review of this follow-up remains with the coordinating owner.

## Independent review and first production ingestion

The coordinating review accepted the lease fencing, resume binding, exact payload hashing and immutable archive snapshot changes. A second review reproduced the full-request-envelope bug, then accepted its fix after the real ZIP boundary regression passed. The final local service suite passed 28 tests and 98 assertions.

The dedicated Worker was deployed as version `016fe765-076b-40f2-ba87-9c6bd1fa4207` at `https://omg-advisories.latham.workers.dev`. Its dedicated D1 database received migration `0001_advisories.sql`; raw records use the private R2 binding. The configured batch limit is 32 records per five-minute Cron invocation, with a 30,000 ms CPU cap. No subscription upgrade was performed. Operator authentication is a deployed secret; no Cloudflare account credential belongs in the Rust client.

The first observed scheduled ingestion completed on 2026-11-13 at 03:35 UTC. Subsequent checks confirmed fresh Arch and KEV checkpoints, 2,444 Arch advisory groups and 1,779 KEV records. An observed D1 query counted 96 CVE records after three scheduled batches, with no database mutation from that verification query. The Arch response's exact payload SHA-256 matched its `payload_json` bytes. An actual CVE lookup also matched its stored payload SHA-256 and reported unknown package applicability. These counts describe those observations, not a completed historical import.

The historical CVE baseline is still unimported and independently unverified. Global bootstrap completeness remains false. Source-local Arch and KEV completion does not establish AUR upstream identity or CVE applicability. Rust client integration and its caller migration remain separate verification work.

## Baseline counter migration and measured D1 reads

The repeated member recount in every import and status request was replaced with a maintained distinct-member counter. The deployed `0001_advisories.sql` remains byte-identical with SHA-256 `85b3a49bf10e44ba2f7b1a67a29f0c4e0417ffe710ba090707238c479f742986`. New migration `0002_baseline_member_counter.sql` reconciles existing session counts once, increments only after a successful new member insert, and rejects member updates/deletes. Current writers use `INSERT ... ON CONFLICT DO NOTHING`. Future member rewriting/removal requires an intentional migration that changes the triggers and reconciles counters. No generic maintenance endpoint was added.

The writer still invalidates caught-up/completed receipts unconditionally, including zero-new-member retries. Status reads `accepted` directly. Finalization still counts actual membership once and now rejects disagreement with either the maintained counter or supplied receipt. Instance/session/digest/origin binding, writer fencing and incomplete full-bootstrap status remain unchanged. Apply `0002` before publishing the new Worker; the previous Worker remains compatible after the migration.

Before the fix, a real Miniflare D1 regression imported 128 and 256 distinct records successfully through the actual service routes. Mutation batch metadata reported 8,912 and 34,208 rows read, while status queries read 133 and 261 rows. The test failed `Expected: <= 4096`, `Received: 8912` for its fixed 32-rows-per-record budget at 128 records. This is actual `meta.rows_read`, rather than SQL-text matching, a timing threshold, or a mock database. Mutation measurements use the real `d1Sql` adapter with a typed `prepare`/`batch` decorator; separate status query instrumentation collects metadata from the same real D1 binding. Per-record point-query reads outside mutation batches and R2 operations are outside the mutation metric.

After the fix, the same successful imports read 784 and 1,568 mutation rows, exactly doubling with the input size. Status reads five rows at both sizes. Fixture storage measured 4,419,200 and 4,525,720 bytes, under its 50 MiB budget; runtimes are disposed and owned scratch removed after each run. These bounded local fixture results are not measurements of a full corpus, production CPU or Cloudflare latency.

Miniflare `5.20261110.0-beta` is now a direct pinned dev dependency, matching the version already installed through Wrangler. The tests apply SQL using the installed Wrangler splitter and real D1 transactional batches. [Cloudflare's D1 SQL documentation](https://developers.cloudflare.com/d1/sql-api/sql-statements/) describes SQLite semantics and recursive trigger controls; successful actual D1 fixture imports also exercise the new trigger. SQLite semantic regressions cover migration reconciliation, distinct retry counting, receipt invalidation, update/delete rejection, rollback of a triggered increment and finalization rejection of counter drift. No remote operation, native build, Git mutation or full archive download occurred in this round. Independent review and the remote migration/deployment remain the coordinating owner's gates.

Final counter-round validation passed 31 tests and 174 assertions. `bun run check`, binding-only `bun run types` and `bun run dry-run` passed. The Worker package is 84.42 KiB, 18.29 KiB gzip. The measured D1 regression remains 784/1,568 mutation rows and five status rows for 128/256 members. Original migration and original 28 tests remain present. No migration or Worker was published in this round.


## Coordinating deployment and client verification

The coordinating owner independently reviewed the integrity and counter changes, applied migrations 0001 and 0002 to the dedicated production database, and deployed Worker version `c19e40a1-a008-4af8-95f8-16c87b485ce0`. No billing plan was changed. The operator secret remains outside this repository.

The production check at 2026-11-13T04:50:11Z verified the exact Arch payload hash, 2,444 issues, fresh Arch and KEV snapshots, unauthorized import rejection, and authenticated malformed import rejection. CVE ingestion reports `delta continuity lost; baseline reconciliation required`. Historical baseline import remains zero, archive verification is false, and bootstrap is incomplete. No complete CVE corpus or AUR applicability claim follows from this deployment.

After comment cleanup, all 31 service tests and 174 assertions, TypeScript checking, and the Wrangler dry run passed. The Rust snapshot client passed 13 boundary tests, the full library suite of 2,343 tests with 13 ignored, and Clippy for default, no-default, and debian-pure builds. A real read-only host audit validated the production snapshot and left the installed package database unchanged. Seven disposable Arch guest scenarios passed with the current CLI, including a user-owned Omarchy checkout whose executable sentinel was never run. These guest checks do not establish LLVM coverage.

The strict coverage comparison still rejects unproved retained execution in changed constructs. Its acceptance rules remain unchanged. This batch is a verified implementation checkpoint, not a declaration that PR #1057 or the full security migration is complete.

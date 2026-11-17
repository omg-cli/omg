# Advisory cache production verification

Verified on 2026-11-16 against the existing OMG account, Worker, D1 database and private R2 bucket. The user supplied current active-credit evidence and explicitly confirmed Workers, D1 and R2 eligibility; no billing credential was needed. Financial account details remain outside Git.

- Source checkout: `1de4e9e28cbda1dc3b36b46b01b82d8465a4c8bd`; the deployed advisory service subtree was clean. Unpublished Rust work was not part of this Worker bundle.
- Worker version: `1ae795ee-841f-4f78-9a99-da9ee600e18e`.
- Endpoint: https://omg-advisories.latham.workers.dev
- Existing five-minute schedule and 32-record batch remain configured.
- Local checks: 51 tests, 395 assertions, zero failures; TypeScript and Wrangler dry-run passed. Actual host Bun was 1.4.2; locked Wrangler was 4.160.0. Total upload 90.86 KiB, gzip 20.14 KiB; reported startup 2 ms.

Recorded a D1 Time Travel bookmark before applying the sole pending migration, `0003_recent_cves.sql`. It adds `source_record_modified_id` on `(modified_at DESC,id DESC)` without rewriting CVE records. The deployed index definition matches the reviewed SQL. `PRAGMA quick_check` returned `ok`; its bounded verification read 405541 rows and wrote none. Database size after migration was 109682688 bytes.

The actual recent-page query plan reports `SEARCH source_record USING INDEX source_record_modified_id`. Returning two records read two rows, wrote none and used 0.6098 ms SQL time in that observation.

Live public verification passed:

- Status stays `no-store` and preserves incomplete baseline metadata.
- Recent first and warm responses have identical bytes and public bounded freshness.
- Matching ETag returns HTTP304 with no body.
- Explicit no-cache revalidation advances the page's `as_of` timestamp.
- Invalid page bounds return HTTP400/no-store.
- Invalid private-ingestion authorization returns HTTP401/no-store without ingestion.
- The original Arch advisory endpoint remains HTTP200 with an ETag.

Single-client observed wall times were 123 ms for the first recent read, 74 ms warm, 83 ms conditional and 198 ms forced revalidation. These observations are not a global latency guarantee or an end-to-end CLI benchmark.

The baseline still reports 132600 imported members, caught_up=false and archive_verified=false. This deployment does not establish full CVE completeness, npm/runtime applicability, EPSS ingestion, Zero Wire redistribution permission or absence of undisclosed zero-days. npm/runtime consent and the remaining release gates are still required.

Detailed local deployment, recovery, query and HTTP receipts are retained under `.git/pr1057-resume-20261115/`; this compact source-controlled receipt preserves their conclusions without storing account credentials or duplicating the database.

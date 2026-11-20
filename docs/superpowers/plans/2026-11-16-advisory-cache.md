# Advisory Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Work solo in the existing checkout.

**Goal:** Serve a bounded rolling 30-day CVE view and conditional cached public reads without weakening source completeness or retaining obsolete freshness claims.

**Architecture:** Query the existing D1 current-record index with an additive modification-time index. Keep raw bodies in private R2 and wrap successful public GET responses with representation ETags and short freshness-bounded cache headers. No external feed is queried on user reads.

**Tech Stack:** Existing TypeScript Worker, D1/SQLite, R2, Bun tests, Miniflare.

**Spec:** docs/superpowers/specs/2026-11-16-advisory-coverage-design.md

## Global Constraints

- Existing main checkout; no new branch/worktree; preserve the recovery stash.
- No deployment, new paid resource or full-corpus enrichment until account quota/credit coverage is verified.
- Thirty days is the data window, not the HTTP freshness lifetime.
- Never cache private requests, errors, stale data or authentication results. Preserve explicit incomplete flags when caching fresh partial data.
- Keep /v1/status uncached and preserve source completeness limitations.
- No new dependency; no changes to CVE ingestion, writer fences or original coverage acceptance.

## Review Focus

- Tied modification timestamps must paginate without losing an ID.
- Cursor tampering and oversized limits must fail before querying data.
- A nearly stale feed must not remain marked complete past its deadline in an HTTP cache.
- A KEV-only change must invalidate a CVE response ETag.
- An old unresolved CVE remains directly retrievable outside the recent view.

### Task 1: Indexed rolling view

**Files:** Create migrations/0003_recent_cves.sql and test/recent.test.ts under services/advisories; modify src/service.ts there. Reuse Store.sql and existing domain validators.

**Interfaces:** GET /v1/cves/recent?limit=100&cursor=... returns schema_version, window_start, as_of, complete, checked_at, records and next_cursor. Records contain RecordRow metadata only; maximum 100 records, default 100. Cursor pins as_of and last (modified_at,id). A new request uses server time. The view contains records modified in [as_of - 30 days, as_of], inclusive, ordered descending by (modified_at,id).

- [x] Add SQLite-backed route tests for bounds, pagination ties, fixed window, old unresolved retention and incomplete source status. Run the tests and retain the expected failing-before result.
- [x] Add the modification-time/ID index and route. Reject unknown/duplicate query parameters and invalid cursors; use prepared values and a limit+1 query.
- [x] Verify the focused tests, existing service tests and type check. Add a real Miniflare D1 page-read measurement with enough old records to expose a full scan.

### Task 2: Conditional public data reads

**Files:** Modify src/service.ts, test/service.test.ts and README.md under services/advisories; add focused tests in test/recent.test.ts where shared fixtures help. Keep the existing handle signature.

**Interfaces:** Public successful fresh data responses return an ETag of their full body and Cache-Control public,max-age=N,must-revalidate, with N <= 60 and bounded by source checked_at + 30 minutes. Fresh partial data retains its explicit incomplete flag. Other responses return no-store. A matching If-None-Match returns 304 with the same cache policy. /v1/status always returns no-store. src/cache.ts owns conditional responses and the Cache API boundary; src/index.ts wires it to caches.default.

- [x] Add failing tests for ETag/304, KEV-only invalidation, stale deadlines and private/error isolation.
- [x] Wrap the existing handler at its public boundary; do not duplicate route logic or read the public body for private/error responses.
- [x] Verify focused and full advisory tests, TypeScript and Wrangler dry run; inspect migration and D1 read cost. Document migration ordering, lack of guaranteed latency and unchanged incomplete baseline.
- [ ] Review the complete diff, commit only this slice and push HEAD:codex/arch-hardening. Keep EPSS ingestion, Zero Wire licensing and runtime adapters as explicitly unfinished follow-up work from the design; none is represented as shipped by this cache slice.

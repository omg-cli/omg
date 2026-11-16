# Package and runtime advisory coverage

The user selected existing feeds, free EPSS and Zero Wire where permitted, and delegated implementation choices. Security coverage includes system packages, managed runtimes and their dependencies. No public feed discovers every undisclosed zero-day.

## Existing behavior and constraints

The advisory Worker already stores original CVE, Arch and CISA KEV data in private R2 with D1 provenance and fenced writers. Public reads require no Cloudflare credentials. Source completeness and freshness are independent. The live full CVE baseline is incomplete; AUR applicability is unknown. Preserve those limitations and all existing admission checks.

Managed runtime installation has version and integrity checks and an EOL report; that is not advisory matching. OSV dependency ecosystems do not automatically describe the interpreter/compiler itself. Distro packages need distro version comparison and backport information; upstream runtimes need vendor ranges and product identity.

Use the existing main checkout. Preserve the original coverage gate, storage discipline and recovery stash. No new dependency for cache headers or SQL pagination. No deployment, new paid resource or full-corpus enrichment until account quota/credit coverage is verified. Feed access being free does not make Cloudflare storage or operations unlimited.

## Data and serving

1. Retain the complete current CVE index, including old and rejected records. Expose a bounded, indexed rolling 30-day view of the latest stored CVE revisions by upstream modification time. This view is not an immutable event log and is not proof that all upstream CVEs were imported. Return provenance, digest, state and independent source completeness; raw bodies remain available through the existing CVE route.
2. Pagination fixes an upper timestamp and orders by modification timestamp and CVE ID. Strictly validate cursors and limits; do not let caller input widen the 30-day window or turn into a fetch URL. Clients overlap refreshes because records can be revised between pages. Future-dated records are excluded from this view, never deleted.
3. Cache successful public data responses for at most 60 seconds, bounded by any shorter freshness deadline. Use a digest of the entire public representation for ETag/304, including provenance and KEV state. Never cache private requests, errors, stale data or authentication results. A fresh but incomplete dataset may be cached with its explicit incomplete flag preserved; caching cannot certify coverage. Thirty days is the data window, not the HTTP freshness lifetime. Keep /v1/status uncached. Any edge-cache hit must expire before its embedded complete/fresh claim can become stale.
4. Keep original R2 data private. No arbitrary URL proxy, inventory upload, personal telemetry, automatic runtime switch or unattended package removal.

## Coverage and prioritization

- CVEProject supplies records; Arch and other supported distro providers establish package applicability; CISA KEV establishes cataloged exploitation. A missing CVE is unavailable evidence, not safety.
- EPSS is optional prioritization, never an applicability or admission decision. Confirmed exploitation outranks a low EPSS probability. FIRST permits free small-batch lookups; a full daily sync must use its CSV, not repeated API queries. Choose a bounded storage/publication approach before adding ingestion; avoid a full D1 score rewrite that exceeds free daily writes. Preserve score date, model, provider, freshness and missing-score state.
- Zero Wire has a working public RSS feed with Cache-Control max-age=300. Treat it as selective contextual intelligence, not an exhaustive package matcher. Radar API data is CC BY-NC 4.0; RSS-specific redistribution permission remains unverified. Until permission is established, retain source links in research, not copied briefing content in the public product.
- Runtime matching must identify vendor, runtime, exact installed/resolved version and provenance. Node Security WG publishes core ranges under MIT; PSF publishes CPython advisories in OSV format, including Git ranges that must not be guessed into release versions; Go's canonical vulnerability service includes toolchain/stdlib records. Unsupported ranges, unknown vendor builds and missing mappings remain unknown.
- Audit installed runtime versions and resolved candidate versions before install/use/update. Apply the existing explicit security policy consistently; do not silently block normal commands merely because a new provider is unavailable. Review paths must display partial coverage and preserve usable last-known evidence. Runtime execution is not a claim that arbitrary application code is sandboxed.

## Verification and release gates

First implement the bounded recent view and conditional caching with behavioral tests against SQLite and the existing Worker harness. Test pagination ties, strict input bounds, old unresolved retention, rejected revisions, expired feed status, ETag changes on KEV/provenance changes and private/error cache isolation. Measure actual D1 rows read for indexed pages.

Then implement EPSS publication and runtime adapters as separate tested changes. Each needs fixtures for affected/fixed boundaries, missing/withdrawn records, unsupported ranges, stale sources, resource bounds and provider failures. Wire runtime CLI, state restoration, direct manager callers, configuration and policy before claiming runtime protection. Keep the original immutable-base coverage and native acceptance obligations open until they pass. Do not claim zero-day prevention or instant latency without measurements.

## Primary research (2026-11-16)

- https://developers.cloudflare.com/changelog/post/2026-11-03-radar-zero-wire/
- https://radar.cloudflare.com/security/zero-wire/rss (HTTP 200; eight items; max-age=300)
- https://developers.cloudflare.com/radar/ (API data license)
- https://www.first.org/epss/data (daily CSV versus lookup API)
- https://www.first.org/epss/faq (free use, requested attribution, probability limits)
- https://github.com/nodejs/security-wg/blob/main/processes/vuln_db.md
- https://github.com/psf/advisory-database
- https://go.dev/doc/security/vuln/database
